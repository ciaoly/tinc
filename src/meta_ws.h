#ifndef TINC_META_WS_H
#define TINC_META_WS_H

#include "connection.h"

typedef struct meta_ws_t meta_ws_t;

extern bool meta_ws_configure(void);
extern void meta_ws_free(connection_t *c);
extern bool meta_ws_start_client(connection_t *c);
extern bool meta_ws_start_server(connection_t *c);
extern bool meta_ws_receive(connection_t *c);
extern bool meta_ws_send(connection_t *c, const void *data, size_t len);
extern bool meta_ws_active(const connection_t *c);
extern bool meta_ws_ready(const connection_t *c);

extern bool meta_ws_enabled;

#endif
