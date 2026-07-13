#include "system.h"

bool meta_ws_enabled = false;

#ifndef HAVE_WSLAY

#include "conf.h"
#include "logger.h"
#include "meta_ws.h"

bool meta_ws_configure(void) {
	char *transport = NULL;
	meta_ws_enabled = false;

	if(get_config_string(lookup_config(&config_tree, "MetaTransport"), &transport)) {
		bool requested = !strcasecmp(transport, "websocket") || !strcasecmp(transport, "ws");

		if(requested) {
			logger(DEBUG_ALWAYS, LOG_ERR, "MetaTransport websocket requires building tinc with -Dwebsocket=enabled and libwslay");
			free(transport);
			return false;
		}

		if(strcasecmp(transport, "tcp") && strcasecmp(transport, "raw")) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Unknown MetaTransport %s", transport);
			free(transport);
			return false;
		}

		free(transport);
	}

	return true;
}

void meta_ws_free(connection_t *c) {
	(void)c;
}

bool meta_ws_start_client(connection_t *c) {
	(void)c;
	return false;
}

bool meta_ws_start_server(connection_t *c) {
	(void)c;
	return false;
}

bool meta_ws_receive(connection_t *c) {
	(void)c;
	return false;
}

bool meta_ws_send(connection_t *c, const void *data, size_t len) {
	(void)c;
	(void)data;
	(void)len;
	return false;
}

bool meta_ws_active(const connection_t *c) {
	(void)c;
	return false;
}

bool meta_ws_ready(const connection_t *c) {
	(void)c;
	return false;
}

#else

#include <wslay/wslay.h>

#include "buffer.h"
#include "conf.h"
#include "logger.h"
#include "meta.h"
#include "meta_ws.h"
#include "netutl.h"
#include "prf.h"
#include "protocol.h"
#include "random.h"
#include "utils.h"
#include "xalloc.h"

#include "chacha-poly1305/chacha-poly1305.h"

#define WS_HANDSHAKE_MAX 8192
#define WS_NONCE_LEN 16
#define WS_ACCEPT_LEN 29
#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

static char *meta_ws_path;
static char *meta_ws_key;

struct meta_ws_t {
	bool client;
	bool established;
	bool failed;
	bool sent_nonce;
	bool got_nonce;
	bool crypto_ready;
	bool send_id_after_rx;
	char *key;
	char accept[WS_ACCEPT_LEN];
	uint8_t local_nonce[WS_NONCE_LEN];
	uint8_t remote_nonce[WS_NONCE_LEN];
	uint64_t inseq;
	uint64_t outseq;
	buffer_t rxbuf;
	wslay_event_context_ptr ctx;
	chacha_poly1305_ctx_t *incipher;
	chacha_poly1305_ctx_t *outcipher;
};

static const char b64_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64encode_standard(const uint8_t *src, size_t len, char *dst) {
	size_t di = 0;

	for(size_t i = 0; i < len; i += 3) {
		uint32_t v = (uint32_t)src[i] << 16;
		size_t remain = len - i;

		if(remain > 1) {
			v |= (uint32_t)src[i + 1] << 8;
		}

		if(remain > 2) {
			v |= src[i + 2];
		}

		dst[di++] = b64_alphabet[(v >> 18) & 63];
		dst[di++] = b64_alphabet[(v >> 12) & 63];
		dst[di++] = remain > 1 ? b64_alphabet[(v >> 6) & 63] : '=';
		dst[di++] = remain > 2 ? b64_alphabet[v & 63] : '=';
	}

	dst[di] = 0;
}

typedef struct sha1_ctx_t {
	uint32_t h[5];
	uint64_t len;
	uint8_t block[64];
	size_t used;
} sha1_ctx_t;

static uint32_t rol32(uint32_t v, unsigned int n) {
	return (v << n) | (v >> (32 - n));
}

static void sha1_block(sha1_ctx_t *ctx, const uint8_t *block) {
	uint32_t w[80];

	for(size_t i = 0; i < 16; i++) {
		w[i] = (uint32_t)block[i * 4] << 24 | (uint32_t)block[i * 4 + 1] << 16 | (uint32_t)block[i * 4 + 2] << 8 | block[i * 4 + 3];
	}

	for(size_t i = 16; i < 80; i++) {
		w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
	}

	uint32_t a = ctx->h[0];
	uint32_t b = ctx->h[1];
	uint32_t c = ctx->h[2];
	uint32_t d = ctx->h[3];
	uint32_t e = ctx->h[4];

	for(size_t i = 0; i < 80; i++) {
		uint32_t f;
		uint32_t k;

		if(i < 20) {
			f = (b & c) | (~b & d);
			k = 0x5A827999;
		} else if(i < 40) {
			f = b ^ c ^ d;
			k = 0x6ED9EBA1;
		} else if(i < 60) {
			f = (b & c) | (b & d) | (c & d);
			k = 0x8F1BBCDC;
		} else {
			f = b ^ c ^ d;
			k = 0xCA62C1D6;
		}

		uint32_t temp = rol32(a, 5) + f + e + k + w[i];
		e = d;
		d = c;
		c = rol32(b, 30);
		b = a;
		a = temp;
	}

	ctx->h[0] += a;
	ctx->h[1] += b;
	ctx->h[2] += c;
	ctx->h[3] += d;
	ctx->h[4] += e;
}

static void sha1_init(sha1_ctx_t *ctx) {
	ctx->h[0] = 0x67452301;
	ctx->h[1] = 0xEFCDAB89;
	ctx->h[2] = 0x98BADCFE;
	ctx->h[3] = 0x10325476;
	ctx->h[4] = 0xC3D2E1F0;
	ctx->len = 0;
	ctx->used = 0;
}

static void sha1_update(sha1_ctx_t *ctx, const void *vdata, size_t len) {
	const uint8_t *data = vdata;
	ctx->len += len * 8;

	while(len) {
		size_t take = sizeof(ctx->block) - ctx->used;

		if(take > len) {
			take = len;
		}

		memcpy(ctx->block + ctx->used, data, take);
		ctx->used += take;
		data += take;
		len -= take;

		if(ctx->used == sizeof(ctx->block)) {
			sha1_block(ctx, ctx->block);
			ctx->used = 0;
		}
	}
}

static void sha1_final(sha1_ctx_t *ctx, uint8_t out[20]) {
	ctx->block[ctx->used++] = 0x80;

	if(ctx->used > 56) {
		memset(ctx->block + ctx->used, 0, sizeof(ctx->block) - ctx->used);
		sha1_block(ctx, ctx->block);
		ctx->used = 0;
	}

	memset(ctx->block + ctx->used, 0, 56 - ctx->used);

	for(size_t i = 0; i < 8; i++) {
		ctx->block[56 + i] = (uint8_t)(ctx->len >> (56 - i * 8));
	}

	sha1_block(ctx, ctx->block);

	for(size_t i = 0; i < 5; i++) {
		out[i * 4] = (uint8_t)(ctx->h[i] >> 24);
		out[i * 4 + 1] = (uint8_t)(ctx->h[i] >> 16);
		out[i * 4 + 2] = (uint8_t)(ctx->h[i] >> 8);
		out[i * 4 + 3] = (uint8_t)ctx->h[i];
	}
}

static void make_accept(const char *key, char out[WS_ACCEPT_LEN]) {
	uint8_t digest[20];
	sha1_ctx_t ctx;
	sha1_init(&ctx);
	sha1_update(&ctx, key, strlen(key));
	sha1_update(&ctx, WS_GUID, sizeof(WS_GUID) - 1);
	sha1_final(&ctx, digest);
	b64encode_standard(digest, sizeof(digest), out);
}

static bool header_contains_token(const char *value, const char *token) {
	size_t tokenlen = strlen(token);

	for(const char *p = value; *p;) {
		while(*p == ' ' || *p == '\t' || *p == ',') {
			p++;
		}

		size_t len = strcspn(p, ",");
		while(len && isspace((uint8_t)p[len - 1])) {
			len--;
		}

		if(len == tokenlen && !strncasecmp(p, token, tokenlen)) {
			return true;
		}

		p += len;
	}

	return false;
}

static bool get_header(const char *headers, const char *name, char *out, size_t outlen) {
	size_t namelen = strlen(name);

	for(const char *line = strstr(headers, "\r\n"); line; line = strstr(line + 2, "\r\n")) {
		line += 2;

		if(!*line || line[0] == '\r') {
			return false;
		}

		const char *line_end = strstr(line, "\r\n");

		if(!line_end) {
			return false;
		}

		const char *colon = memchr(line, ':', (size_t)(line_end - line));

		if(colon && (size_t)(colon - line) == namelen && !strncasecmp(line, name, namelen)) {
			const char *value = colon + 1;

			while(value < line_end && isspace((uint8_t)*value)) {
				value++;
			}

			while(line_end > value && isspace((uint8_t)line_end[-1])) {
				line_end--;
			}

			size_t len = (size_t)(line_end - value);

			if(len >= outlen) {
				return false;
			}

			memcpy(out, value, len);
			out[len] = 0;
			return true;
		}
	}

	return false;
}

static ssize_t find_header_end(const buffer_t *buf) {
	for(uint32_t i = buf->offset; i + 3 < buf->len; i++) {
		if(!memcmp(buf->data + i, "\r\n\r\n", 4)) {
			return (ssize_t)(i + 4 - buf->offset);
		}
	}

	return -1;
}

static bool ws_init_context(connection_t *c);

static bool ws_flush(connection_t *c) {
	meta_ws_t *ws = c->meta_ws;
	uint8_t out[16384];

	while(wslay_event_want_write(ws->ctx)) {
		ssize_t written = wslay_event_write(ws->ctx, out, sizeof(out));

		if(written < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "WebSocket write failed for %s (%s)", c->name, c->hostname);
			return false;
		}

		if(!written) {
			break;
		}

		logger(DEBUG_META, LOG_DEBUG, "Queued %ld bytes of WebSocket metadata framing for %s (%s)",
		       (long)written, c->name, c->hostname);
		buffer_add(&c->outbuf, (const char *)out, (uint32_t)written);
	}

	if(c->outbuf.len) {
		io_set(&c->io, IO_READ | IO_WRITE);
	}

	return true;
}

static bool derive_keys(connection_t *c) {
	meta_ws_t *ws = c->meta_ws;
	uint8_t seed[sizeof("tinc websocket meta") - 1 + WS_NONCE_LEN * 2];
	uint8_t keymat[CHACHA_POLY1305_KEYLEN * 2];
	uint8_t *p = seed;

	memcpy(p, "tinc websocket meta", sizeof("tinc websocket meta") - 1);
	p += sizeof("tinc websocket meta") - 1;
	memcpy(p, ws->client ? ws->local_nonce : ws->remote_nonce, WS_NONCE_LEN);
	p += WS_NONCE_LEN;
	memcpy(p, ws->client ? ws->remote_nonce : ws->local_nonce, WS_NONCE_LEN);

	if(!prf((const uint8_t *)ws->key, strlen(ws->key), seed, sizeof(seed), keymat, sizeof(keymat))) {
		return false;
	}

	ws->incipher = chacha_poly1305_init();
	ws->outcipher = chacha_poly1305_init();

	if(!ws->incipher || !ws->outcipher) {
		memzero(keymat, sizeof(keymat));
		return false;
	}

	uint8_t *client_key = keymat;
	uint8_t *server_key = keymat + CHACHA_POLY1305_KEYLEN;
	bool ok = chacha_poly1305_set_key(ws->outcipher, ws->client ? client_key : server_key) &&
	          chacha_poly1305_set_key(ws->incipher, ws->client ? server_key : client_key);
	memzero(keymat, sizeof(keymat));

	if(!ok) {
		return false;
	}

	ws->crypto_ready = true;
	logger(DEBUG_CONNECTIONS, LOG_INFO, "WebSocket metadata encryption ready for %s (%s)", c->name, c->hostname);
	return true;
}

static bool send_nonce(connection_t *c) {
	meta_ws_t *ws = c->meta_ws;
	uint8_t msg[1 + WS_NONCE_LEN];

	if(!ws->key || ws->sent_nonce) {
		return true;
	}

	randomize(ws->local_nonce, sizeof(ws->local_nonce));
	msg[0] = 0;
	memcpy(msg + 1, ws->local_nonce, WS_NONCE_LEN);
	logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Sending WebSocket metadata crypto nonce to %s (%s)", c->name, c->hostname);

	struct wslay_event_msg frame = {
		.opcode = WSLAY_BINARY_FRAME,
		.msg = msg,
		.msg_length = sizeof(msg),
	};

	if(wslay_event_queue_msg(ws->ctx, &frame)) {
		return false;
	}

	ws->sent_nonce = true;
	return ws_flush(c);
}

static bool ws_established(connection_t *c) {
	meta_ws_t *ws = c->meta_ws;
	ws->established = true;
	logger(DEBUG_CONNECTIONS, LOG_INFO, "WebSocket metadata transport established with %s (%s)",
	       c->name, c->hostname);

	if(!ws_init_context(c)) {
		return false;
	}

	if(!send_nonce(c)) {
		return false;
	}

	if(!ws->key && ws->client) {
		return send_id(c);
	}

	return true;
}

static bool handle_message(connection_t *c, const uint8_t *msg, size_t len) {
	meta_ws_t *ws = c->meta_ws;

	if(ws->key && !ws->crypto_ready) {
		if(len != 1 + WS_NONCE_LEN || msg[0]) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Invalid WebSocket metadata crypto handshake from %s (%s)", c->name, c->hostname);
			return false;
		}

		memcpy(ws->remote_nonce, msg + 1, WS_NONCE_LEN);
		ws->got_nonce = true;
		logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Received WebSocket metadata crypto nonce from %s (%s)", c->name, c->hostname);

		if(!ws->sent_nonce && !send_nonce(c)) {
			return false;
		}

		if(!derive_keys(c)) {
			return false;
		}

		if(ws->client) {
			ws->send_id_after_rx = true;
		}

		return true;
	}

	if(ws->key) {
		if(len < 16) {
			return false;
		}

		uint8_t *plain = alloca(len);
		size_t plainlen = len;

		if(!chacha_poly1305_decrypt(ws->incipher, ws->inseq++, msg, len, plain, &plainlen)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not decrypt WebSocket metadata from %s (%s)", c->name, c->hostname);
			return false;
		}

		logger(DEBUG_META, LOG_DEBUG, "Received %lu decrypted WebSocket metadata bytes from %s (%s)",
		       (unsigned long)plainlen, c->name, c->hostname);
		return receive_meta_bytes(c, plain, (ssize_t)plainlen);
	}

	logger(DEBUG_META, LOG_DEBUG, "Received %lu WebSocket metadata bytes from %s (%s)",
	       (unsigned long)len, c->name, c->hostname);
	return receive_meta_bytes(c, msg, (ssize_t)len);
}

static void on_msg_recv(wslay_event_context_ptr ctx, const struct wslay_event_on_msg_recv_arg *arg, void *user_data) {
	(void)ctx;
	connection_t *c = user_data;

	if(arg->opcode == WSLAY_CONNECTION_CLOSE) {
		c->meta_ws->failed = true;
		return;
	}

	if(arg->opcode != WSLAY_BINARY_FRAME) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unexpected WebSocket metadata opcode from %s (%s)", c->name, c->hostname);
		c->meta_ws->failed = true;
		return;
	}

	if(!handle_message(c, arg->msg, arg->msg_length)) {
		c->meta_ws->failed = true;
	}
}

static ssize_t recv_cb(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, int flags, void *user_data) {
	(void)flags;
	connection_t *c = user_data;
	buffer_t *rx = &c->meta_ws->rxbuf;

	if(rx->len <= rx->offset) {
		wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
		return -1;
	}

	uint32_t avail = rx->len - rx->offset;

	if(len > avail) {
		len = avail;
	}

	memcpy(buf, rx->data + rx->offset, len);
	buffer_read(rx, (uint32_t)len);
	return (ssize_t)len;
}

static ssize_t send_cb(wslay_event_context_ptr ctx, const uint8_t *data, size_t len, int flags, void *user_data) {
	(void)ctx;
	(void)flags;
	connection_t *c = user_data;
	buffer_add(&c->outbuf, (const char *)data, (uint32_t)len);
	io_set(&c->io, IO_READ | IO_WRITE);
	return (ssize_t)len;
}

static int genmask_cb(wslay_event_context_ptr ctx, uint8_t *buf, size_t len, void *user_data) {
	(void)ctx;
	(void)user_data;
	randomize(buf, len);
	return 0;
}

static bool ws_init_context(connection_t *c) {
	meta_ws_t *ws = c->meta_ws;
	struct wslay_event_callbacks callbacks = {
		.recv_callback = recv_cb,
		.send_callback = send_cb,
		.genmask_callback = genmask_cb,
		.on_msg_recv_callback = on_msg_recv,
	};

	int result = ws->client ?
	             wslay_event_context_client_init(&ws->ctx, &callbacks, c) :
	             wslay_event_context_server_init(&ws->ctx, &callbacks, c);

	if(result) {
		return false;
	}

	wslay_event_config_set_max_recv_msg_length(ws->ctx, MAXBUFSIZE + 64);
	return true;
}

static bool parse_client_response(connection_t *c, size_t header_len) {
	meta_ws_t *ws = c->meta_ws;
	char *headers = xmalloc(header_len + 1);
	memcpy(headers, ws->rxbuf.data + ws->rxbuf.offset, header_len);
	headers[header_len] = 0;

	bool ok = !strncmp(headers, "HTTP/1.1 101", 12) || !strncmp(headers, "HTTP/1.0 101", 12);
	char upgrade[64];
	char connection[128];
	char accept[64];

	ok = ok &&
	     get_header(headers, "Upgrade", upgrade, sizeof(upgrade)) && !strcasecmp(upgrade, "websocket") &&
	     get_header(headers, "Connection", connection, sizeof(connection)) && header_contains_token(connection, "upgrade") &&
	     get_header(headers, "Sec-WebSocket-Accept", accept, sizeof(accept)) && !strcmp(accept, ws->accept);

	free(headers);
	buffer_read(&ws->rxbuf, (uint32_t)header_len);

	if(!ok) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Invalid WebSocket Upgrade response from %s (%s)", c->name, c->hostname);
		return false;
	}

	logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Accepted WebSocket Upgrade response from %s (%s)", c->name, c->hostname);
	return ws_established(c);
}

static bool parse_server_request(connection_t *c, size_t header_len) {
	meta_ws_t *ws = c->meta_ws;
	char *headers = xmalloc(header_len + 1);
	memcpy(headers, ws->rxbuf.data + ws->rxbuf.offset, header_len);
	headers[header_len] = 0;

	char path[256];
	bool ok = sscanf(headers, "GET %255s HTTP/1.%*d", path) == 1 && !strcmp(path, meta_ws_path);
	char upgrade[64];
	char connection[128];
	char version[8];
	char key[64];
	char accept[WS_ACCEPT_LEN];

	ok = ok &&
	     get_header(headers, "Upgrade", upgrade, sizeof(upgrade)) && !strcasecmp(upgrade, "websocket") &&
	     get_header(headers, "Connection", connection, sizeof(connection)) && header_contains_token(connection, "upgrade") &&
	     get_header(headers, "Sec-WebSocket-Version", version, sizeof(version)) && !strcmp(version, "13") &&
	     get_header(headers, "Sec-WebSocket-Key", key, sizeof(key)) && strlen(key) == 24;

	if(ok) {
		make_accept(key, accept);
		char response[256];
		int len = snprintf(response, sizeof(response),
		                   "HTTP/1.1 101 Switching Protocols\r\n"
		                   "Upgrade: websocket\r\n"
		                   "Connection: Upgrade\r\n"
		                   "Sec-WebSocket-Accept: %s\r\n"
		                   "\r\n", accept);
		buffer_add(&c->outbuf, response, (uint32_t)len);
		io_set(&c->io, IO_READ | IO_WRITE);
	}

	free(headers);
	buffer_read(&ws->rxbuf, (uint32_t)header_len);

	if(!ok) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Invalid WebSocket Upgrade request from %s", c->hostname);
		return false;
	}

	logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Accepted WebSocket Upgrade request from %s on path %s", c->hostname, meta_ws_path);
	return ws_established(c);
}

static bool process_ws_rx(connection_t *c) {
	meta_ws_t *ws = c->meta_ws;

	if(!ws->established) {
		ssize_t header_len = find_header_end(&ws->rxbuf);

		if(header_len < 0) {
			if(ws->rxbuf.len - ws->rxbuf.offset > WS_HANDSHAKE_MAX) {
				logger(DEBUG_ALWAYS, LOG_ERR, "WebSocket Upgrade header too large from %s (%s)", c->name, c->hostname);
				return false;
			}

			return true;
		}

		if(ws->client) {
			if(!parse_client_response(c, (size_t)header_len)) {
				return false;
			}
		} else if(!parse_server_request(c, (size_t)header_len)) {
			return false;
		}
	}

	while(ws->rxbuf.len > ws->rxbuf.offset && wslay_event_want_read(ws->ctx)) {
		int result = wslay_event_recv(ws->ctx);

		if(result) {
			logger(DEBUG_ALWAYS, LOG_ERR, "WebSocket receive failed for %s (%s)", c->name, c->hostname);
			return false;
		}

		if(ws->failed) {
			return false;
		}
	}

	if(ws->send_id_after_rx) {
		ws->send_id_after_rx = false;

		if(!send_id(c)) {
			return false;
		}
	}

	return ws_flush(c);
}

bool meta_ws_configure(void) {
	char *transport = NULL;
	meta_ws_enabled = false;

	if(get_config_string(lookup_config(&config_tree, "MetaTransport"), &transport)) {
		if(!strcasecmp(transport, "websocket") || !strcasecmp(transport, "ws")) {
			meta_ws_enabled = true;
		} else if(strcasecmp(transport, "tcp") && strcasecmp(transport, "raw")) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Unknown MetaTransport %s", transport);
			free(transport);
			return false;
		}

		free(transport);
	}

	free(meta_ws_path);
	meta_ws_path = NULL;

	if(!get_config_string(lookup_config(&config_tree, "MetaWebSocketPath"), &meta_ws_path)) {
		meta_ws_path = xstrdup("/tinc");
	}

	if(meta_ws_path[0] != '/' || strchr(meta_ws_path, '\r') || strchr(meta_ws_path, '\n') || strchr(meta_ws_path, ' ')) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Invalid MetaWebSocketPath");
		return false;
	}

	free_string(meta_ws_key);
	meta_ws_key = NULL;
	get_config_string(lookup_config(&config_tree, "MetaWebSocketKey"), &meta_ws_key);

	if(meta_ws_key && !*meta_ws_key) {
		logger(DEBUG_ALWAYS, LOG_ERR, "MetaWebSocketKey cannot be empty");
		return false;
	}

	if(meta_ws_enabled) {
		logger(DEBUG_CONNECTIONS, LOG_INFO, "Using WebSocket metadata transport on path %s%s",
		       meta_ws_path, meta_ws_key ? " with PSK encryption" : "");
	}

	return true;
}

static meta_ws_t *new_ws(bool client) {
	meta_ws_t *ws = xzalloc(sizeof(*ws));
	ws->client = client;

	if(meta_ws_key) {
		ws->key = xstrdup(meta_ws_key);
	}

	return ws;
}

void meta_ws_free(connection_t *c) {
	if(!c || !c->meta_ws) {
		return;
	}

	meta_ws_t *ws = c->meta_ws;
	wslay_event_context_free(ws->ctx);
	chacha_poly1305_exit(ws->incipher);
	chacha_poly1305_exit(ws->outcipher);
	buffer_clear(&ws->rxbuf);
	free_string(ws->key);
	memzero(ws, sizeof(*ws));
	free(ws);
	c->meta_ws = NULL;
}

bool meta_ws_start_client(connection_t *c) {
	if(c->meta_ws) {
		return true;
	}

	c->meta_ws = new_ws(true);
	logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Starting WebSocket metadata client handshake with %s (%s) on path %s",
	       c->name, c->hostname, meta_ws_path);
	uint8_t rawkey[16];
	char key[25];
	randomize(rawkey, sizeof(rawkey));
	b64encode_standard(rawkey, sizeof(rawkey), key);
	make_accept(key, c->meta_ws->accept);

	char *host = NULL;
	char *port = NULL;
	sockaddr2str(&c->address, &host, &port);

	char request[1024];
	int len = snprintf(request, sizeof(request),
	                   "GET %s HTTP/1.1\r\n"
	                   "Host: %s:%s\r\n"
	                   "Upgrade: websocket\r\n"
	                   "Connection: Upgrade\r\n"
	                   "Sec-WebSocket-Key: %s\r\n"
	                   "Sec-WebSocket-Version: 13\r\n"
	                   "\r\n", meta_ws_path, host, port, key);
	free(host);
	free(port);

	buffer_add(&c->outbuf, request, (uint32_t)len);
	logger(DEBUG_META, LOG_DEBUG, "Queued WebSocket Upgrade request for %s (%s)", c->name, c->hostname);
	io_set(&c->io, IO_READ | IO_WRITE);
	return true;
}

bool meta_ws_start_server(connection_t *c) {
	if(c->meta_ws) {
		return true;
	}

	c->meta_ws = new_ws(false);
	logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Expecting WebSocket metadata server handshake from %s", c->hostname);
	return true;
}

bool meta_ws_receive(connection_t *c) {
	meta_ws_t *ws = c->meta_ws;
	char inbuf[MAXBUFSIZE];
	ssize_t inlen = recv(c->socket, inbuf, sizeof(inbuf), 0);

	if(inlen <= 0) {
		if(!inlen || !sockerrno) {
			logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Connection closed by %s (%s)", c->name, c->hostname);
		} else if(sockwouldblock(sockerrno)) {
			return true;
		} else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Metadata socket read error for %s (%s): %s", c->name, c->hostname, sockstrerror(sockerrno));
		}

		return false;
	}

	buffer_add(&ws->rxbuf, inbuf, (uint32_t)inlen);
	logger(DEBUG_META, LOG_DEBUG, "Read %ld WebSocket transport bytes from %s (%s)", (long)inlen, c->name, c->hostname);
	return process_ws_rx(c);
}

bool meta_ws_send(connection_t *c, const void *data, size_t len) {
	meta_ws_t *ws = c->meta_ws;

	if(!ws || !ws->established || (ws->key && !ws->crypto_ready)) {
		return false;
	}

	const uint8_t *msg = data;
	size_t msglen = len;
	uint8_t *encrypted = NULL;

	if(ws->key) {
		encrypted = alloca(len + 16);
		msglen = len + 16;

		if(!chacha_poly1305_encrypt(ws->outcipher, ws->outseq++, data, len, encrypted, &msglen)) {
			return false;
		}

		msg = encrypted;
	}

	struct wslay_event_msg frame = {
		.opcode = WSLAY_BINARY_FRAME,
		.msg = msg,
		.msg_length = msglen,
	};

	if(wslay_event_queue_msg(ws->ctx, &frame)) {
		return false;
	}

	logger(DEBUG_META, LOG_DEBUG, "Queued %lu metadata bytes as WebSocket binary message for %s (%s)%s",
	       (unsigned long)len, c->name, c->hostname, ws->key ? " with AEAD" : "");
	return ws_flush(c);
}

bool meta_ws_active(const connection_t *c) {
	return c && c->meta_ws && c->meta_ws->established;
}

bool meta_ws_ready(const connection_t *c) {
	return c && c->meta_ws && c->meta_ws->established && (!c->meta_ws->key || c->meta_ws->crypto_ready);
}

#endif
