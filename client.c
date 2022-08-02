/*
 *
 *	client.c
 *
 *	Client-specific functions
 *
 */

#include "ipoud.h"

#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>

struct in_addr ipou_tun_gw4;
struct in6_addr ipou_tun_gw6;

static uint8_t ipou_client_id;
static uint16_t ipou_session_id;  /* network byte order */
static time_t ipou_last_msg;
static _Bool ipou_server_quiet;
static union ipou_msg_route *ipou_saved_routes;
static uint8_t ipou_route_count;

static void ipou_client_add_routes(void)
{
	unsigned int i;
	size_t size;

	ipou_route_count = ipou_buf.welcome.num_routes;

	if (ipou_route_count > 0) {

		size = ipou_route_count * sizeof *ipou_saved_routes;
		ipou_saved_routes = IPOU_ZALLOC(size);
		memcpy(ipou_saved_routes, ipou_buf.welcome.routes, size);
	}

	for (i = 0; i < ipou_route_count; ++i) {

		if (ipou_buf.welcome.routes[i].family == AF_INET6) {

			ipou_add_route6(&ipou_buf.welcome.routes[i].r6,
					&ipou_tun_gw6);
			continue;
		}

		IPOU_ASSERT(ipou_buf.welcome.routes[i].family == AF_INET);

		ipou_add_route4(&ipou_buf.welcome.routes[i].r4[0],
				ipou_tun_gw4);

		if (ipou_buf.welcome.routes[i].r4[1].family == AF_INET) {

			ipou_add_route4(&ipou_buf.welcome.routes[i].r4[1],
					ipou_tun_gw4);
		}

	}
}

__attribute__((noreturn))
static void ipou_client_bad_proto(void)
{
	char server[IPOU_PROTOVER_STRLEN], client[IPOU_PROTOVER_STRLEN];

	IPOU_FATAL("Protocol version mismatch: server is %s; client is %s",
		   ipou_fmt_protover(ipou_buf.bad_proto.proto_ver, server),
		   ipou_fmt_protover(IPOU_PROTO_VER, client));
}

static void ipou_client_hello(const uint8_t id)
{
	int err;

	ipou_buf.hello.hdr.msg_type = IPOU_MSG_HELLO;
	ipou_buf.hello.hdr.client_id = id;
	ipou_buf.hello.hdr.session_id = 0;
	ipou_buf.hello.proto_ver = IPOU_PROTO_VER;
	ipou_sendmsg(NULL, sizeof ipou_buf.hello);

	if ((err = ipou_recvmsg(NULL, 0)) == 0)
		IPOU_FATAL("Timeout waiting for response from server");
	else if (err < 0)
		IPOU_FATAL("Invalid response from server");

	switch (ipou_buf.hdr.msg_type) {

		case IPOU_MSG_WELCOME:
			break;

		case IPOU_MSG_BUSY:
			IPOU_FATAL("Max number of clients connected to server");

		case IPOU_MSG_BAD_PROTO:
			ipou_client_bad_proto();  /* does not return */

		default:
			IPOU_FATAL("Unexpected response to HELLO message: %s",
				   ipou_msg_types[ipou_buf.hdr.msg_type].name);
	}

	ipou_last_msg = time(NULL);
	ipou_server_quiet = 0;
}

static void ipou_client_welcome(void)
{
	ipou_client_id = ipou_buf.welcome.hdr.client_id;
	ipou_session_id = ipou_buf.welcome.hdr.session_id;
	ipou_tun_addr6 = ipou_buf.welcome.addr6;
	ipou_tun_gw6 = ipou_buf.welcome.gateway6;
	ipou_tun_addr4 = ipou_buf.welcome.addr4;
	ipou_tun_gw4 = ipou_buf.welcome.gateway4;
	ipou_max_msg_size = ntohs(ipou_buf.welcome.max_msg_size);
	ipou_tun_pfx6 = ipou_buf.welcome.pfx_len6;
	ipou_tun_pfx4 = ipou_buf.welcome.pfx_len4;

	ipou_tun_setup();
	ipou_client_add_routes();

	ipou_buf.hdr.msg_type = IPOU_MSG_READY;
	ipou_sendmsg(NULL, ipou_max_msg_size);
}

void ipou_client_setup(void)
{
	char addrbuf[IPOU_SOCK_ADDRSTRLEN], verbuf[IPOU_PROTOVER_STRLEN];
	ipou_client_socket();
	ipou_client_hello(IPOU_ID_NONE);
	ipou_client_welcome();

	IPOU_NOTICE("IP over UDP client ready; "
				"connected to %s (protocol version %s)",
		    ipou_sock_ntop(&ipou_server.sin6, addrbuf),
		    ipou_fmt_protover(IPOU_PROTO_VER, verbuf));
}

void ipou_client_shutdown(void)
{
	ipou_buf.hdr.msg_type = IPOU_MSG_GOODBYE;
	ipou_buf.hdr.client_id = ipou_client_id;
	ipou_buf.hdr.session_id = ipou_session_id;
	ipou_sendmsg(NULL, sizeof ipou_buf.hdr);

	if (close(ipou_tun_fd) != 0)
		IPOU_PFATAL("close");

	if (close(ipou_socket_fd) != 0)
		IPOU_PFATAL("close");

	if (ipou_route_count > 0)
		free(ipou_saved_routes);

	IPOU_NOTICE("IP over UDP client exiting normally");
}

static void ipou_client_bad_session(void)
{
	IPOU_INFO("Server has restarted; attempting renegotiation");

	ipou_client_hello(ipou_client_id);

	if (ipou_client_id != ipou_buf.welcome.hdr.client_id
		|| memcmp(&ipou_tun_addr6, &ipou_buf.welcome.addr6, 16) != 0
		|| memcmp(&ipou_tun_gw6, &ipou_buf.welcome.gateway6, 16) != 0
		|| ipou_tun_addr4.s_addr != ipou_buf.welcome.addr4.s_addr
		|| ipou_tun_gw4.s_addr != ipou_buf.welcome.gateway4.s_addr
		|| ipou_max_msg_size != ntohs(ipou_buf.welcome.max_msg_size)
		|| ipou_tun_pfx6 != ipou_buf.welcome.pfx_len6
		|| ipou_tun_pfx4 != ipou_buf.welcome.pfx_len4
		|| ipou_route_count != ipou_buf.welcome.num_routes
		|| memcmp(ipou_saved_routes, ipou_buf.welcome.routes,
			  ipou_route_count * sizeof *ipou_saved_routes) != 0
	) {
		ipou_exit_flag = IPOU_CLIENT_EXIT_RENEG;
		return;
	}

	ipou_session_id = ipou_buf.hdr.session_id;

	IPOU_INFO("Session renegotiation succeded");
}

static _Bool ipou_client_pkt_ok4(const char *restrict const src,
				 const char *restrict const dst)
{
	const char *err;

	err = ipou_pkt_client_err4(ipou_tun_addr4, ipou_tun_gw4);
	if (err == NULL)
		return 1;

	IPOU_PKTLOG("Dropping IPv4 packet from %s to %s: %s", src, dst, err);

	return 0;
}

static _Bool ipou_client_pkt_ok6(const char *restrict const src,
				 const char *restrict const dst)
{
	const char *err;

	err = ipou_pkt_client_err6(&ipou_tun_addr6, &ipou_tun_gw6);
	if (err == NULL)
		return 1;

	IPOU_PKTLOG("Dropping IPv6 packet from %s to %s: %s", src, dst, err);

	return 0;
}

static void ipou_client_tun_in(void)
{
	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
	ssize_t pkt_size;

	while ((pkt_size = ipou_recvpkt(src, dst)) != 0) {

		if (pkt_size < 0)
			continue;

		if (ipou_buf.pkt.ip.version == 4) {
			if (!ipou_client_pkt_ok4(src, dst))
				continue;
			ipou_buf.pkt.hdr.msg_type = IPOU_MSG_PACKET4;
		}
		else {
			if (!ipou_client_pkt_ok6(src, dst))
				continue;
			ipou_buf.pkt.hdr.msg_type = IPOU_MSG_PACKET6;
		}

		ipou_buf.pkt.hdr.client_id = ipou_client_id;
		ipou_buf.pkt.hdr.session_id = ipou_session_id;

		ipou_sendmsg(NULL, sizeof ipou_buf.pkt.hdr + pkt_size);

		IPOU_PKTLOG("Forwarded packet from %s to %s to server",
			    src, dst);
	}
}

static const char *ipou_client_pkt_err4(void)
{
	if (ipou_tun_addr4.s_addr == INADDR_ANY)
		return "TUN IPv4 address not set";

	if (ipou_buf.pkt.ip4.dest_addr.s_addr != ipou_tun_addr4.s_addr)
		return "destination is not local TUN IPv4 address";

	if (ipou_in_net4(ipou_buf.pkt.ip4.source_addr,
				ipou_tun_netaddr4, ipou_tun_netmask4)
			&& ipou_buf.pkt.ip4.source_addr.s_addr
				!= ipou_tun_gw4.s_addr) {
		return "source is not server TUN IPv4 address";
	}

	return NULL;
}

static const char *ipou_client_pkt_err6(void)
{
	if (IN6_IS_ADDR_UNSPECIFIED(&ipou_tun_addr6))
		return "TUN IPv6 address not set";

	if (memcmp(&ipou_buf.pkt.ip6.dest_addr, &ipou_tun_addr6, 16) != 0)
		return "destination is not local TUN IPv6 address";

	if (ipou_in_net6(&ipou_buf.pkt.ip6.source_addr, &ipou_tun_netaddr6,
							&ipou_tun_netmask6)
			&& memcmp(&ipou_buf.pkt.ip6.source_addr,
							&ipou_tun_gw6, 16)
				!= 0) {

		return "source is not server TUN IPv6 address";
	}

	return NULL;
}

static void ipou_client_msg_pkt(void)
{
	char srcbuf[INET6_ADDRSTRLEN], dstbuf[INET6_ADDRSTRLEN];
	size_t pkt_size;
	ssize_t bytes;
	const char *err;

	if (ipou_buf.pkt.ip.version == 4) {

		pkt_size = ipou_pkt4_size();
		err = ipou_client_pkt_err4();

		if (ipou_log_pkts || err != NULL) {
			inet_ntop(AF_INET, &ipou_buf.pkt.ip4.source_addr,
				  srcbuf, sizeof srcbuf);
			inet_ntop(AF_INET, &ipou_buf.pkt.ip4.dest_addr,
				  dstbuf, sizeof dstbuf);
		}
	}
	else {
		pkt_size = ipou_pkt6_size();
		err = ipou_client_pkt_err6();

		if (ipou_log_pkts || err != NULL) {
			inet_ntop(AF_INET6, &ipou_buf.pkt.ip6.source_addr,
				  srcbuf, sizeof srcbuf);
			inet_ntop(AF_INET6, &ipou_buf.pkt.ip6.dest_addr,
				  dstbuf, sizeof dstbuf);
		}
	}

	if (err != NULL) {
		IPOU_ERR("Ignoring ** BAD ** packet from server (%s -> %s): %s",
			 srcbuf, dstbuf, err);
		return;
	}

	if ((bytes = write(ipou_tun_fd, ipou_buf.hdr.data, pkt_size)) < 0)
		IPOU_PFATAL("write");

	IPOU_ASSERT((size_t)bytes == pkt_size);

	IPOU_PKTLOG("TUN packet sent: %zd bytes from %s to %s",
		    bytes, srcbuf, dstbuf);
}

static void ipou_client_ping(void)
{
	ipou_buf.hdr.msg_type = IPOU_MSG_PONG;
	/* Just got PING, so client_id & session_id are already set */
	ipou_sendmsg(NULL, sizeof ipou_buf.hdr);
}

static _Bool ipou_client_session_ok(void)
{
	if (!ipou_msg_types[ipou_buf.hdr.msg_type].has_session)
		return 1;

	if (ipou_buf.hdr.client_id != ipou_client_id
			|| ipou_buf.hdr.session_id != ipou_session_id) {

		IPOU_INFO("Ignoring message from server: invalid session ID");
		return 0;
	}

	ipou_last_msg = time(NULL);

	if (ipou_server_quiet) {
		ipou_server_quiet = 0;
		IPOU_DEBUG("Server marked READY");
	}

	return 1;
}

static void ipou_client_sock_in(void)
{
	int err;

	while((err = ipou_recvmsg(NULL, MSG_DONTWAIT)) != 0) {

		if (err < 0 || !ipou_client_session_ok())
			continue;

		switch (ipou_buf.hdr.msg_type) {

			case IPOU_MSG_PACKET4:
			case IPOU_MSG_PACKET6:
				ipou_client_msg_pkt();
				continue;

			case IPOU_MSG_BAD_SESSION:
				ipou_client_bad_session();
				return;

			case IPOU_MSG_GOODBYE:
				ipou_exit_flag = IPOU_CLIENT_EXIT_GOODBYE;
				return;

			case IPOU_MSG_PING:
				ipou_client_ping();
				continue;

			case IPOU_MSG_PONG:
				continue;  /* see ipou_client_session_ok() */

			case IPOU_MSG_HELLO:
			case IPOU_MSG_WELCOME:
			case IPOU_MSG_BUSY:
			case IPOU_MSG_READY:
			case IPOU_MSG_BAD_PROTO:
				break;
		}

		IPOU_ERR("Ignoring unexpected message (%s) from server",
			 ipou_msg_types[ipou_buf.hdr.msg_type].name);
	}
}

void ipou_client_process(const struct pollfd *const pfds)
{
	int elapsed;

	if (pfds[0].revents & POLLIN)
		ipou_client_sock_in();
	if (pfds[1].revents & POLLIN)
		ipou_client_tun_in();

	elapsed = time(NULL) - ipou_last_msg;

	if (elapsed < 0) {

		IPOU_WARNING("System clock may have rolled over; "
				" restarting server timeout");

		ipou_last_msg = time(NULL);
		ipou_server_quiet = 0;
	}
	else if (elapsed > ipou_peer_timeout) {

		IPOU_INFO("Server unresponsive for %d seconds",
			  ipou_peer_timeout / 2);  /* time we've been PINGing */

		ipou_exit_flag = IPOU_CLIENT_EXIT_TIMEOUT;
	}
	else if (elapsed > ipou_peer_timeout / 2) {

		IPOU_DEBUG("Nothing from server for %d seconds; marked QUIET",
			   elapsed);

		ipou_server_quiet = 1;

		ipou_buf.hdr.msg_type = IPOU_MSG_PING;
		ipou_buf.hdr.client_id = ipou_client_id;
		ipou_buf.hdr.session_id = ipou_session_id;
		ipou_sendmsg(NULL, sizeof ipou_buf.hdr);
	}
}
