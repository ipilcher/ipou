/*
 *
 *	server.c
 *
 *	Server-specific functions
 *
 */

#include "ipoud.h"

#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>

enum ipou_client_state {
	IPOU_CLIENT_AVAIL = 0,	/* no client with this ID exists */
	IPOU_CLIENT_WELCOME,	/* WELCOME sent; waiting for READY message */
	IPOU_CLIENT_READY,	/* READY message received */
	IPOU_CLIENT_QUIET,	/* no recent traffic; KEEPALIVE sent */
};

struct ipou_client {
	union ipou_sockaddr	client;
	struct in6_addr		tun_ip6;
	time_t			last_msg;  /* last message received time */
	struct in_addr		tun_ip4;
	uint16_t		session_id;  /* network byte order */
	enum ipou_client_state	state;
};

static struct ipou_client *ipou_clients;

void ipou_server_setup(void)
{
	char addrbuf[IPOU_SOCK_ADDRSTRLEN], verbuf[IPOU_PROTOVER_STRLEN];
	uint32_t pool4;
	uint8_t i;

	ipou_clients = IPOU_ZALLOC(ipou_max_clients * sizeof *ipou_clients);
	pool4 = ntohl(ipou_pool4.s_addr);

	for (i = 0; i < ipou_max_clients; ++i) {

		if (pool4 != INADDR_ANY)
			ipou_clients[i].tun_ip4.s_addr = htonl(pool4 + i);

		if (!IN6_IS_ADDR_UNSPECIFIED(&ipou_pool6)) {
			ipou_clients[i].tun_ip6 = ipou_pool6;
			ipou_addr_add6(&ipou_clients[i].tun_ip6, i);
		}
	}

	ipou_server_socket();
	ipou_tun_setup();

	IPOU_NOTICE("IP over UDP server ready; "
				"listening on %s (protocol version %s)",
		    ipou_sock_ntop(&ipou_server.sin6, addrbuf),
		    ipou_fmt_protover(IPOU_PROTO_VER, verbuf));
}

static uint8_t ipou_hello_find_id(const char *restrict const addrbuf)
{
	uint8_t i;

	for (i = 0; i < ipou_max_clients; ++i) {

		if (ipou_clients[i].state == IPOU_CLIENT_AVAIL)
			return i;
	}

	IPOU_INFO("No ID available for client %s", addrbuf);

	return IPOU_ID_NONE;
}

static uint8_t ipou_hello_client_id(const char *restrict const addrbuf)
{
	if (ipou_buf.hdr.client_id == IPOU_ID_NONE)
		return ipou_hello_find_id(addrbuf);

	if (ipou_buf.hdr.client_id >= ipou_max_clients) {
		IPOU_INFO("Ignoring client %s requested ID %hhu: out of range",
			  addrbuf, ipou_buf.hdr.client_id);
		return ipou_hello_find_id(addrbuf);
	}

	if (ipou_clients[ipou_buf.hdr.client_id].state != IPOU_CLIENT_AVAIL) {
		IPOU_INFO("Ignoring client %s requested ID %hhu: not available",
			  addrbuf, ipou_buf.hdr.client_id);
		return ipou_hello_find_id(addrbuf);
	}

	return ipou_buf.hdr.client_id;
}

static uint16_t ipou_server_session_id(const time_t now)
{
	_Static_assert(sizeof(time_t) % sizeof(uint16_t) == 0,
		       "time_t size not multiple of uint16_t size");

	union {
		time_t		time;
		uint16_t	words[sizeof(time_t) / sizeof(uint16_t)];
	} seed;

	unsigned int i;
	uint16_t id;

	seed.time = now;
	id = 0;

	for (i = 0; i < sizeof(time_t) / sizeof(uint16_t); ++i)
		id ^= seed.words[i];

	return id;
}

static void ipou_hello_add_routes(void)
{
	union ipou_msg_route *route;
	struct ipou_cfg_route6 *cr6;
	struct ipou_cfg_route4 *cr4;
	_Bool i;

	route = ipou_buf.welcome.routes;

	for (cr6 = ipou_cfg_routes6; cr6 != NULL; cr6 = cr6->next) {

		route->r6.family = AF_INET6;
		route->r6.pfx_len = cr6->pfx_len;
		route->r6.dest = cr6->dest;

		++route;
	}

	i = 0;

	for (cr4 = ipou_cfg_routes4; cr4 != NULL; cr4 = cr4->next) {

		route->r4[i].family = AF_INET;
		route->r4[i].pfx_len = cr4->pfx_len;
		route->r4[i].dest = cr4->dest;

		i = !i;
		if (i == 0)
			++route;
	}

	if (i == 1)
		route->r4[i].family = AF_UNSPEC;
}

static void ipou_server_msg_hello(const union ipou_sockaddr *const addr)
{
	char server[IPOU_PROTOVER_STRLEN], client[IPOU_PROTOVER_STRLEN];
	char addrbuf[IPOU_SOCK_ADDRSTRLEN];
	uint8_t id;

	/* Don't need to optimize this, so just format the client address */
	ipou_sock_ntop(&addr->sin6, addrbuf);

	if (ipou_buf.hello.proto_ver != IPOU_PROTO_VER) {

		IPOU_INFO("Protocol version mismatch; "
					"server is %s; client (%s) is %s",
			  ipou_fmt_protover(IPOU_PROTO_VER, server), addrbuf,
			  ipou_fmt_protover(ipou_buf.hello.proto_ver, client));

		memset(&ipou_buf.bad_proto, 0 , sizeof ipou_buf.bad_proto);
		ipou_buf.bad_proto.hdr.msg_type = IPOU_MSG_BAD_PROTO;
		ipou_buf.bad_proto.proto_ver = IPOU_PROTO_VER;
		ipou_sendmsg(addr, sizeof ipou_buf.bad_proto);
		return;
	}

	if ((id = ipou_hello_client_id(addrbuf)) == IPOU_ID_NONE) {

		IPOU_INFO("No client ID available for %s", addrbuf);
		memset(&ipou_buf.hdr, 0, sizeof ipou_buf.hdr);
		ipou_buf.hdr.msg_type = IPOU_MSG_BUSY;
		ipou_sendmsg(addr, sizeof ipou_buf.hdr);
		return;
	}

	ipou_clients[id].client.sin6 = addr->sin6;
	ipou_clients[id].last_msg = time(NULL);
	ipou_clients[id].session_id =
		htons(ipou_server_session_id(ipou_clients[id].last_msg));
	ipou_clients[id].state = IPOU_CLIENT_WELCOME;

	/* Entire WELCOME message must be initialized for client checksum */
	ipou_buf.welcome.hdr.msg_type = IPOU_MSG_WELCOME;
	ipou_buf.welcome.hdr.client_id = id;
	ipou_buf.welcome.hdr.session_id = ipou_clients[id].session_id;
	ipou_buf.welcome.addr6 = ipou_clients[id].tun_ip6;
	ipou_buf.welcome.gateway6 = ipou_tun_addr6;
	ipou_buf.welcome.addr4 = ipou_clients[id].tun_ip4;
	ipou_buf.welcome.gateway4 = ipou_tun_addr4;
	ipou_buf.welcome.max_msg_size = htons(ipou_max_msg_size);
	ipou_buf.welcome.pfx_len6 = ipou_tun_pfx6;
	ipou_buf.welcome.pfx_len4 = ipou_tun_pfx4;
	ipou_buf.welcome.num_routes = ipou_hello_routes;
	memset(&ipou_buf.welcome.__zeroes, 0, sizeof ipou_buf.welcome.__zeroes);

	if (ipou_hello_routes != 0) {
		memset(&ipou_buf.welcome.routes, 0,
		       sizeof ipou_buf.welcome.routes[0] * ipou_hello_routes);
		ipou_hello_add_routes();
	}

	ipou_sendmsg(addr, ipou_max_msg_size);
}

static _Bool ipou_server_session_ok(const union ipou_sockaddr *const addr)
{
	char addrbuf[IPOU_SOCK_ADDRSTRLEN];

	if (!ipou_msg_types[ipou_buf.hdr.msg_type].has_session)
		return 1;

	if (ipou_buf.hdr.client_id >= ipou_max_clients) {

		IPOU_INFO("Ignoring message from %s: invalid client ID (%hhu)",
			  ipou_sock_ntop(&addr->sin6, addrbuf),
			  ipou_buf.hdr.client_id);
		memset(&ipou_buf.hdr, 0, sizeof ipou_buf.hdr);
		ipou_buf.hdr.msg_type = IPOU_MSG_BAD_SESSION;
		ipou_sendmsg(addr, sizeof ipou_buf.hdr);
		return 0;
	}

	if (ipou_clients[ipou_buf.hdr.client_id].state == IPOU_CLIENT_AVAIL
			|| ipou_clients[ipou_buf.hdr.client_id].session_id
				!= ipou_buf.hdr.session_id) {

		IPOU_INFO("Ignoring message from %s: invalid session ID",
			  ipou_sock_ntop(&addr->sin6, addrbuf));
		memset(&ipou_buf.hdr, 0, sizeof ipou_buf.hdr);
		ipou_buf.hdr.msg_type = IPOU_MSG_BAD_SESSION;
		ipou_sendmsg(addr, sizeof ipou_buf.hdr);
		return 0;
	}

	ipou_clients[ipou_buf.hdr.client_id].last_msg = time(NULL);

	if (ipou_clients[ipou_buf.hdr.client_id].state == IPOU_CLIENT_QUIET) {
		ipou_clients[ipou_buf.hdr.client_id].state = IPOU_CLIENT_READY;
		IPOU_DEBUG("Client %hhu (%s) marked READY",
			   ipou_buf.hdr.client_id,
			   ipou_sock_ntop(&addr->sin6, addrbuf));
	}

	return 1;
}

static void ipou_server_msg_ready(const union ipou_sockaddr *const addr)
{
	char addrbuf[IPOU_SOCK_ADDRSTRLEN];

	ipou_sock_ntop(&addr->sin6, addrbuf);

	if (ipou_clients[ipou_buf.hdr.client_id].state
						!= IPOU_CLIENT_WELCOME) {

		IPOU_INFO("Ignoring READY message from %s: %s",
			  addrbuf, "client state not WELCOME");
		return;
	}

	ipou_clients[ipou_buf.hdr.client_id].state = IPOU_CLIENT_READY;

	IPOU_INFO("New client %hhu (%s) marked READY",
		   ipou_buf.hdr.client_id, addrbuf);
}

static void ipou_server_msg_goodbye(const union ipou_sockaddr *const addr)
{
	char buf[IPOU_SOCK_ADDRSTRLEN];

	ipou_clients[ipou_buf.hdr.client_id].state = IPOU_CLIENT_AVAIL;

	IPOU_INFO("Client %hhu (%s) said GOODBYE",
		   ipou_buf.hdr.client_id, ipou_sock_ntop(&addr->sin6, buf));
}

static void ipou_server_msg_ping(const union ipou_sockaddr *const addr)
{
	ipou_buf.hdr.msg_type = IPOU_MSG_PONG;
	/* Just got PING, so client_id & session_id are already set */
	ipou_sendmsg(addr, sizeof ipou_buf.hdr);
}

static void ipou_server_msg_pkt(const union ipou_sockaddr *const addr)
{
	char srcbuf[INET6_ADDRSTRLEN], dstbuf[INET6_ADDRSTRLEN];
	char addrbuf[IPOU_SOCK_ADDRSTRLEN];
	size_t pkt_size;
	ssize_t bytes;
	const char *err;
	uint8_t client_id;

	client_id = ipou_buf.hdr.client_id;

	if (ipou_clients[client_id].state != IPOU_CLIENT_READY) {
		IPOU_INFO("Ignoring PACKET message from %s: %s",
			  ipou_sock_ntop(&addr->sin6, addrbuf),
			  "client state not READY");
		return;
	}

	if (ipou_buf.pkt.ip.version == 4) {

		pkt_size = ipou_pkt4_size();
		err = ipou_pkt_client_err4(ipou_clients[client_id].tun_ip4,
					   ipou_tun_addr4);

		if (ipou_log_pkts || err != NULL) {
			inet_ntop(AF_INET, &ipou_buf.pkt.ip4.source_addr,
				  srcbuf, sizeof srcbuf);
			inet_ntop(AF_INET, &ipou_buf.pkt.ip4.dest_addr,
				  dstbuf, sizeof dstbuf);
		}
	}
	else {
		pkt_size = ipou_pkt6_size();
		err = ipou_pkt_client_err6(&ipou_clients[client_id].tun_ip6,
					   &ipou_tun_addr6);

		if (ipou_log_pkts || err != NULL) {
			inet_ntop(AF_INET6, &ipou_buf.pkt.ip6.source_addr,
				  srcbuf, sizeof srcbuf);
			inet_ntop(AF_INET6, &ipou_buf.pkt.ip6.dest_addr,
				  dstbuf, sizeof dstbuf);
		}
	}

	if (err != NULL) {
		IPOU_ERR("Ignoring ** BAD ** packet from %s (%s -> %s): %s",
			 ipou_sock_ntop(&addr->sin6, addrbuf),
			 srcbuf, dstbuf, err);
		return;
	}

	if ((bytes = write(ipou_tun_fd, ipou_buf.hdr.data, pkt_size)) < 0)
		IPOU_PFATAL("write");

	IPOU_ASSERT((size_t)bytes == pkt_size);

	IPOU_PKTLOG("TUN packet sent: %zd bytes from %s to %s",
		    bytes, srcbuf, dstbuf);
}

static void ipou_server_sock_in(void)
{
	char addrbuf[IPOU_SOCK_ADDRSTRLEN];
	union ipou_sockaddr addr;
	int err;

	while ((err = ipou_recvmsg(&addr, MSG_DONTWAIT)) != 0) {

		if (err < 0 || !ipou_server_session_ok(&addr))
			continue;

		switch (ipou_buf.hdr.msg_type) {

			case IPOU_MSG_PACKET4:
			case IPOU_MSG_PACKET6:
				ipou_server_msg_pkt(&addr);
				continue;

			case IPOU_MSG_HELLO:
				ipou_server_msg_hello(&addr);
				continue;

			case IPOU_MSG_READY:
				ipou_server_msg_ready(&addr);
				continue;

			case IPOU_MSG_GOODBYE:
				ipou_server_msg_goodbye(&addr);
				continue;

			case IPOU_MSG_PING:
				ipou_server_msg_ping(&addr);
				continue;

			case IPOU_MSG_PONG:
				return;  /* see ipou_server_session_ok() */

			case IPOU_MSG_WELCOME:
			case IPOU_MSG_BUSY:
			case IPOU_MSG_BAD_SESSION:
			case IPOU_MSG_BAD_PROTO:
				break;
		}

		IPOU_ERR("Ignoring unexpected message (%s) from %s",
			 ipou_msg_types[ipou_buf.hdr.msg_type].name,
			 ipou_sock_ntop(&addr.sin6, addrbuf));
	}
}

static uint8_t ipou_server_pkt_client4(const char *restrict const src,
				       const char *restrict const dst)
{
	uint32_t id;

	id = ntohl(ipou_buf.pkt.ip4.dest_addr.s_addr)
						- ntohl(ipou_pool4.s_addr);
	if (id <= ipou_max_clients
		&& (ipou_clients[id].state == IPOU_CLIENT_READY
			|| ipou_clients[id].state == IPOU_CLIENT_QUIET)) {
		return id;
	}

	IPOU_PKTLOG("Dropping IPv4 packet from %s to %s: %s",
		    src, dst, "no client with that TUN address");

	ipou_send_dest_unreach4(src);

	return IPOU_ID_NONE;
}

static uint8_t ipou_server_pkt_client6(char *restrict const src,
				       char *restrict const dst)
{
	uint32_t id;

	/*
	 * Only need to look at last 32 bits of addresses.  See
	 * ipou_validate_server_ipv6() in config.c.
	 */
	id = ntohl(ipou_buf.pkt.ip6.dest_addr.__in6_u.__u6_addr32[3])
				- ntohl(ipou_pool6.__in6_u.__u6_addr32[3]);

	if (id <= ipou_max_clients
		&& (ipou_clients[id].state == IPOU_CLIENT_READY
			|| ipou_clients[id].state == IPOU_CLIENT_QUIET)) {
		return id;
	}

	IPOU_PKTLOG("Dropping IPv6 packet from %s to %s: %s",
		    src, dst, "no client with that TUN address");

	ipou_send_dest_unreach6(src);

	return IPOU_ID_NONE;
}

static _Bool ipou_server_pkt_ok4(const char *restrict const src,
				 const char *restrict const dst)
{
	if (ipou_tun_addr4.s_addr == INADDR_ANY) {
		IPOU_PKTLOG("Dropping IPv4 packet from %s to %s: %s",
			    src, dst, "IPv4 TUN address/pool not set");
		return 0;
	}

	if (!ipou_in_net4(ipou_buf.pkt.ip4.dest_addr,
				ipou_tun_netaddr4, ipou_tun_netmask4)) {
		IPOU_PKTLOG("Dropping IPv4 packet from %s to %s: %s",
			    src, dst, "destination not in TUN subnet");
		return 0;
	}

	return 1;
}

static _Bool ipou_server_pkt_ok6(const char *restrict const src,
				 const char *restrict const dst)
{
	if (IN6_IS_ADDR_UNSPECIFIED(&ipou_tun_addr6)) {
		IPOU_PKTLOG("Dropping IPv6 packet from %s to %s: %s",
			    src, dst, "IPv6 TUN address/pool not set");
		return 0;
	}

	if (!ipou_in_net6(&ipou_buf.pkt.ip6.dest_addr,
				&ipou_tun_netaddr6, &ipou_tun_netmask6)) {
		IPOU_PKTLOG("Dropping IPv6 packet from %s to %s: %s",
			    src, dst, "destination not in TUN subnet");
		return 0;
	}

	return 1;
}

static void ipou_server_tun_in(void)
{
	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
	char addrbuf[IPOU_SOCK_ADDRSTRLEN];
	ssize_t pkt_size;
	uint32_t client_id;

	while ((pkt_size = ipou_recvpkt(src, dst)) != 0) {

		if (pkt_size < 0)
			continue;

		if (ipou_buf.pkt.ip.version == 4) {
			if (!ipou_server_pkt_ok4(src, dst))
				continue;
			ipou_buf.pkt.hdr.msg_type = IPOU_MSG_PACKET4;
			client_id = ipou_server_pkt_client4(src, dst);
		}
		else {
			if (!ipou_server_pkt_ok6(src, dst))
				continue;
			ipou_buf.pkt.hdr.msg_type = IPOU_MSG_PACKET6;
			client_id = ipou_server_pkt_client6(src, dst);
		}

		if (client_id == IPOU_ID_NONE)
			continue;

		ipou_buf.pkt.hdr.client_id = client_id;
		ipou_buf.pkt.hdr.session_id =
					ipou_clients[client_id].session_id;

		ipou_sendmsg(&ipou_clients[client_id].client,
			     sizeof ipou_buf.pkt.hdr + pkt_size);

		IPOU_PKTLOG("Forwarded packet from %s to %s to %s", src, dst,
			ipou_sock_ntop(&ipou_clients[client_id].client.sin6,
				       addrbuf));
	}
}

static _Bool ipou_check_client(const uint8_t id, const time_t now, _Bool warned)
{
	char addrbuf[IPOU_SOCK_ADDRSTRLEN];
	int elapsed;

	elapsed = now - ipou_clients[id].last_msg;

	if (elapsed < 0) {

		if (!warned) {
			IPOU_WARNING("System clock may have rolled over"
						" restarting client timeouts");
			warned = 1;
		}

		ipou_clients[id].last_msg = now;

		if (ipou_clients[id].state == IPOU_CLIENT_QUIET)
			ipou_clients[id].state = IPOU_CLIENT_READY;
	}
	else if (elapsed > ipou_peer_timeout) {

		IPOU_INFO("Client %s unresponsive for %d seconds; "
							"disconnecting",
			  ipou_sock_ntop(&ipou_clients[id].client.sin6,
					 addrbuf),
			  ipou_peer_timeout / 2);  /* time we've been PINGing */

		ipou_clients[id].state = IPOU_CLIENT_AVAIL;
	}
	else if (elapsed > ipou_peer_timeout / 2) {

		IPOU_DEBUG("Nothing from client %s for %d seconds; "
							"marked QUIET",
			   ipou_sock_ntop(&ipou_clients[id].client.sin6,
					  addrbuf),
			   elapsed);

		ipou_clients[id].state = IPOU_CLIENT_QUIET;

		ipou_buf.hdr.msg_type = IPOU_MSG_PING;
		ipou_buf.hdr.client_id = id;
		ipou_buf.hdr.session_id = ipou_clients[id].session_id;
		ipou_sendmsg(&ipou_clients[id].client, sizeof ipou_buf.hdr);
	}

	return warned;
}



void ipou_server_process(const struct pollfd *const pfds)
{
	unsigned int i;
	time_t now;
	_Bool warned;

	if (pfds[0].revents & POLLIN)
		ipou_server_sock_in();
	if (pfds[1].revents & POLLIN)
		ipou_server_tun_in();

	now = time(NULL);
	warned = 0;

	for (i = 0; i < ipou_max_clients; ++i) {

		if (ipou_clients[i].state != IPOU_CLIENT_AVAIL)
			warned = ipou_check_client(i, now, warned);
	}
}

void ipou_server_shutdown(void)
{
	uint8_t i;

	ipou_buf.hdr.msg_type = IPOU_MSG_GOODBYE;

	for (i = 0; i < ipou_max_clients; ++i) {

		if (ipou_clients[i].state == IPOU_CLIENT_AVAIL)
			continue;

		ipou_buf.hdr.client_id = i;
		ipou_buf.hdr.session_id = ipou_clients[i].session_id;

		ipou_sendmsg(&ipou_clients[i].client, sizeof ipou_buf.hdr);
	}

	free(ipou_clients);

		if (close(ipou_tun_fd) != 0)
		IPOU_PFATAL("close");

	if (close(ipou_socket_fd) != 0)
		IPOU_PFATAL("close");

	IPOU_NOTICE("IP over UDP server exiting normally");
}
