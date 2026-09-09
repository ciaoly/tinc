/*
    device.c -- Interaction with the Wintun driver
    Copyright (C) 2002-2005 Ivo Timmermans,
                  2002-2022 Guus Sliepen <guus@tinc-vpn.org>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "../system.h"

#include <windows.h>

/* MinGW's <sal.h> does not define every extended SAL annotation that the
   official wintun.h uses. Provide harmless fallbacks so the header compiles
   regardless of the toolchain. */
#ifndef _Must_inspect_result_
#define _Must_inspect_result_
#endif
#ifndef _Return_type_success_
#define _Return_type_success_(x)
#endif
#ifndef _Post_writable_byte_size_
#define _Post_writable_byte_size_(x)
#endif

#include "../conf.h"
#include "../device.h"
#include "../ethernet.h"
#include "../logger.h"
#include "../names.h"
#include "../net.h"
#include "../route.h"
#include "../utils.h"
#include "../xalloc.h"

#include "wintun.h"

/* Wintun is a layer-3 (raw IP) driver, unlike the old TAP-Windows driver which
   is layer-2 (Ethernet frames). tinc's routing code, however, always works on
   Ethernet frames: route() reads the EtherType from DATA(packet)[12..13] and
   the IP payload from DATA(packet) + ether_size (14 bytes). To bridge the two
   worlds we synthesise a 14-byte Ethernet header around every raw IP packet we
   read (zero MACs + an EtherType derived from the IP version nibble) and strip
   that header again before writing. This is the same trick tinc uses on Linux
   for its TUN (layer-3) device, and it lets Wintun nodes interoperate with TAP
   nodes unchanged: the on-wire protocol always carries an Ethernet frame. */

#define ETH_HEADER_LEN 14
#define WINTUN_RING_CAPACITY 0x400000 /* 4 MiB */
#define WINTUN_DLL "wintun.dll"

/* Function pointers, loaded from wintun.dll at runtime. The Wintun library is
   only ever shipped as a signed DLL and must be loaded dynamically. */
static WINTUN_CREATE_ADAPTER_FUNC *WintunCreateAdapter;
static WINTUN_OPEN_ADAPTER_FUNC *WintunOpenAdapter;
static WINTUN_CLOSE_ADAPTER_FUNC *WintunCloseAdapter;
static WINTUN_START_SESSION_FUNC *WintunStartSession;
static WINTUN_END_SESSION_FUNC *WintunEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC *WintunGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC *WintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC *WintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC *WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC *WintunSendPacket;

static HMODULE wintun_lib = NULL;
static WINTUN_ADAPTER_HANDLE adapter_handle = NULL;
static WINTUN_SESSION_HANDLE session_handle = NULL;
static HANDLE read_event = NULL;
static bool adapter_created = false; /* true if we created it this run (removed on close) */

int device_fd = -1;
char *device = NULL;
char *iface = NULL;
static io_t device_read_io;
static vpn_packet_t device_read_packet;
static const char *device_info = "Windows wintun device";

static bool load_wintun(void) {
	wintun_lib = LoadLibraryA(WINTUN_DLL);

	if(!wintun_lib) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not load %s: %s", WINTUN_DLL, winerror(GetLastError()));
		logger(DEBUG_ALWAYS, LOG_ERR, "Please place a signed wintun.dll (from https://www.wintun.net/) next to tincd.exe.");
		return false;
	}

	bool ok = true;
#define LOAD(name) \
	do { \
		*(FARPROC *)&name = GetProcAddress(wintun_lib, #name); \
		if(!name) { \
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not find %s in %s: %s", #name, WINTUN_DLL, winerror(GetLastError())); \
			ok = false; \
		} \
	} while(0)

	LOAD(WintunCreateAdapter);
	LOAD(WintunOpenAdapter);
	LOAD(WintunCloseAdapter);
	LOAD(WintunStartSession);
	LOAD(WintunEndSession);
	LOAD(WintunGetReadWaitEvent);
	LOAD(WintunReceivePacket);
	LOAD(WintunReleaseReceivePacket);
	LOAD(WintunAllocateSendPacket);
	LOAD(WintunSendPacket);
#undef LOAD

	if(!ok) {
		FreeLibrary(wintun_lib);
		wintun_lib = NULL;
		return false;
	}

	return true;
}

/* Derive a deterministic GUID from the adapter name so the Windows NLA network
   profile stays stable across tinc restarts. Not cryptographically strong. */
static void name_to_guid(const char *name, GUID *guid) {
	static const unsigned char base[16] = {
		0x2a, 0x8c, 0x6d, 0x7e, 0x1f, 0x4b, 0x3a, 0x4d,
		0x9b, 0x5e, 0x10, 0x84, 0x6f, 0x2a, 0x3d, 0xc1
	};

	unsigned char *p = (unsigned char *)guid;
	memcpy(p, base, 16);

	for(const unsigned char *s = (const unsigned char *)name; *s; s++) {
		for(int i = 0; i < 16; i++) {
			p[i] = (unsigned char)(p[i] * 33u + *s + (unsigned)i);
		}
	}
}

/* Wintun delivers raw IP packets. Frame them as Ethernet for tinc's router. */
static void device_handle_read(void *data, int flags) {
	(void)data;
	(void)flags;

	for(;;) {
		DWORD size;
		BYTE *p = WintunReceivePacket(session_handle, &size);

		if(!p) {
			DWORD err = GetLastError();

			if(err != ERROR_NO_MORE_ITEMS) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Error while reading from %s %s: %s", device_info,
				       device, winerror(err));
			}

			/* ERROR_NO_MORE_ITEMS just means the ring is drained; the read
			   event will be signalled again when more data arrives. */
			break;
		}

		/* Only IPv4 and IPv6 make sense on a layer-3 device. */
		unsigned char version = (p[0] >> 4) & 0xf;

		if(version != 4 && version != 6) {
			WintunReleaseReceivePacket(session_handle, p);
			continue;
		}

		if((size_t)size + ETH_HEADER_LEN > MAXSIZE) {
			logger(DEBUG_ALWAYS, LOG_WARNING, "Received overlong packet (%lu bytes) from %s %s, dropping",
			       (unsigned long)size, device_info, device);
			WintunReleaseReceivePacket(session_handle, p);
			continue;
		}

		uint8_t *frame = device_read_packet.data;

		/* Synthesise the Ethernet header: zeroed dst/src MAC + EtherType. */
		memset(frame, 0, 12);

		if(version == 4) {
			frame[12] = 0x08;
			frame[13] = 0x00;
		} else {
			frame[12] = 0x86;
			frame[13] = 0xDD;
		}

		memcpy(frame + ETH_HEADER_LEN, p, size);
		WintunReleaseReceivePacket(session_handle, p);

		device_read_packet.len = size + ETH_HEADER_LEN;
		device_read_packet.priority = 0;

		route(myself, &device_read_packet);
	}
}

static bool setup_device(void) {
	if(!load_wintun()) {
		return false;
	}

	get_config_string(lookup_config(&config_tree, "Device"), &device);
	get_config_string(lookup_config(&config_tree, "Interface"), &iface);

	if(device && iface) {
		logger(DEBUG_ALWAYS, LOG_WARNING, "Warning: both Device and Interface specified, results may not be as expected");
	}

	/* The Wintun adapter is identified by name. Prefer Interface, then the
	   tinc network name, then "tinc". The old Device/Interface settings are
	   reused: either may name the adapter. */
	const char *name = iface ? iface : (device ? device : (netname ? netname : "tinc"));

	wchar_t wname[256];

	if(!MultiByteToWideChar(CP_ACP, 0, name, -1, wname, sizeof(wname) / sizeof(wname[0]))) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Invalid adapter name %s: %s", name, winerror(GetLastError()));
		return false;
	}

	/* Reuse an adapter left over from a previous run if present, otherwise
	   create one. Wintun installs its driver on demand, so unlike TAP-Windows
	   there is no separate driver installation step. */
	adapter_handle = WintunOpenAdapter(wname);
	adapter_created = false;

	if(!adapter_handle) {
		GUID guid;
		name_to_guid(name, &guid);

		adapter_handle = WintunCreateAdapter(wname, L"tinc", &guid);

		if(!adapter_handle) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Could not open or create Wintun adapter %s: %s", name, winerror(GetLastError()));
			return false;
		}

		adapter_created = true;
		logger(DEBUG_ALWAYS, LOG_INFO, "Created Wintun adapter %s", name);
	} else {
		logger(DEBUG_ALWAYS, LOG_INFO, "Opened existing Wintun adapter %s", name);
	}

	/* Keep device/iface consistent for logging and the tinc-up/down scripts,
	   which receive $DEVICE and $INTERFACE. */
	if(!device) {
		device = xstrdup(name);
	}

	if(!iface) {
		iface = xstrdup(name);
	}

	/* Wintun adapters have no MAC address at all: the driver is a pure
	   layer-3 NDIS miniport (NdisMediumIP) that implements no 802.3 address
	   OIDs, so the interface table reports a zero-length physical address,
	   permanently. There is therefore nothing to query, unlike with the old
	   layer-2 TAP-Windows driver. This is harmless because we synthesise and
	   strip the Ethernet header around every packet (see the top of this
	   file): mymac never reaches the network stack and is never read from
	   it. In router mode - the only sensible mode for a layer-3 device -
	   tinc routes on IP subnets, not on MAC addresses, so nodes in one VPN
	   may all share the default MAC from route.c without any effect. */
	if(routing_mode == RMODE_ROUTER) {
		overwrite_mac = 1;
	}

	session_handle = WintunStartSession(adapter_handle, WINTUN_RING_CAPACITY);

	if(!session_handle) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not start Wintun session on %s (%s): %s", device, iface, winerror(GetLastError()));
		return false;
	}

	read_event = WintunGetReadWaitEvent(session_handle);

	device_info = "Windows wintun device";

	logger(DEBUG_ALWAYS, LOG_INFO, "%s (%s) is a %s", device, iface, device_info);

	return true;
}

static void enable_device(void) {
	logger(DEBUG_ALWAYS, LOG_INFO, "Enabling %s", device_info);

	/* The session is already active; just register the read wait event with
	   the event loop and drain anything already queued. */
	io_add_event(&device_read_io, device_handle_read, NULL, read_event);
	device_handle_read(NULL, 0);
}

static void disable_device(void) {
	logger(DEBUG_ALWAYS, LOG_INFO, "Disabling %s", device_info);

	io_del(&device_read_io);
}

static void close_device(void) {
	if(session_handle) {
		WintunEndSession(session_handle);
		session_handle = NULL;
		/* read_event is owned by the session; do not close it. */
		read_event = NULL;
	}

	if(adapter_handle) {
		/* WintunCloseAdapter removes adapters created with WintunCreateAdapter
		   and merely releases handles opened with WintunOpenAdapter. Removing
		   on close matches tinc's tinc-up/tinc-down lifecycle: the adapter
		   (and its IP configuration) lives exactly while tincd runs. */
		WintunCloseAdapter(adapter_handle);
		adapter_handle = NULL;
		adapter_created = false;
	}

	if(wintun_lib) {
		FreeLibrary(wintun_lib);
		wintun_lib = NULL;
	}

	free(device);
	device = NULL;
	free(iface);
	iface = NULL;
	device_info = NULL;
}

static bool read_packet(vpn_packet_t *packet) {
	/* Reads are event-driven via device_handle_read(); this entry point is unused. */
	(void)packet;
	return false;
}

static bool write_packet(vpn_packet_t *packet) {
	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Writing packet of %d bytes to %s",
	       packet->len, device_info);

	if(packet->len < ETH_HEADER_LEN) {
		return false;
	}

	/* Wintun only accepts raw IP. Strip the synthesised Ethernet header and
	   drop anything that is not IPv4/IPv6 (e.g. ARP). */
	uint16_t type = DATA(packet)[12] << 8 | DATA(packet)[13];

	if(type != ETH_P_IP && type != ETH_P_IPV6) {
		logger(DEBUG_TRAFFIC, LOG_DEBUG, "Dropping non-IP frame (type %hx) to %s", type, device_info);
		return true;
	}

	DWORD iplen = packet->len - ETH_HEADER_LEN;
	BYTE *buf = WintunAllocateSendPacket(session_handle, iplen);

	if(!buf) {
		DWORD err = GetLastError();

		if(err == ERROR_BUFFER_OVERFLOW) {
			/* Ring full: apply backpressure by dropping. */
			logger(DEBUG_TRAFFIC, LOG_WARNING, "Wintun send ring full, dropping packet to %s", device_info);
			return true;
		}

		logger(DEBUG_ALWAYS, LOG_ERR, "Error while writing to %s %s: %s", device_info, device, winerror(err));
		return false;
	}

	memcpy(buf, DATA(packet) + ETH_HEADER_LEN, iplen);
	WintunSendPacket(session_handle, buf);

	return true;
}

const devops_t os_devops = {
	.setup = setup_device,
	.close = close_device,
	.read = read_packet,
	.write = write_packet,
	.enable = enable_device,
	.disable = disable_device,
};
