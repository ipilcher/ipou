/*
 *
 *	message.c
 *
 *	Client/server messages & socket
 *
 */


#include "ipoud.h"

#include <errno.h>

int ipou_socket_fd;

static const int ipou_pmtudisc_do = IP_PMTUDISC_DO;

static const char *ipou_ck_pkt4_size(size_t msg_size);
static const char *ipou_ck_pkt6_size(size_t msg_size);
static const char *ipou_ck_ready_size(size_t msg_size);
static const char *ipou_ck_welcome_size(size_t msg_size);

const struct ipou_msg_type_t ipou_msg_types[] = {
	[IPOU_MSG_PACKET4] = {
		.name		= "IPv4 PACKET",
		.cksize		= ipou_ck_pkt4_size,
		.min_size	= sizeof(struct ipou_msg_hdr)
					+ sizeof(struct ipou_ip4_hdr),
		.has_session	= 1
	},
	[IPOU_MSG_PACKET6] = {
		.name		= "IPv6 PACKET",
		.cksize		= ipou_ck_pkt6_size,
		.min_size	= sizeof(struct ipou_msg_hdr)
					+ sizeof(struct ipou_ip6_hdr),
		.has_session	= 1
	},
	[IPOU_MSG_HELLO] = {
		.name		= "HELLO",
		.cksize		= NULL,
		.min_size	= sizeof(struct ipou_msg_hello),
		.has_session	= 0
	},
	[IPOU_MSG_WELCOME] = {
		.name		= "WELCOME",
		.cksize		= ipou_ck_welcome_size,
		.min_size	= IPOU_MIN_PATH_MTU - IPOU_IPUDP_HDR_SIZE6,
		.has_session	= 1
	},
	[IPOU_MSG_BUSY] = {
		.name		= "BUSY",
		.cksize		= NULL,
		.min_size	= sizeof(struct ipou_msg_hdr),
		.has_session	= 0
	},
	[IPOU_MSG_READY] = {
		.name		= "READY",
		.cksize		= ipou_ck_ready_size,
		.min_size	= IPOU_MIN_PATH_MTU - IPOU_IPUDP_HDR_SIZE6,
		.has_session	= 1
	},
	[IPOU_MSG_BAD_SESSION] = {
		.name		= "INVALID SESSION",
		.cksize		= NULL,
		.min_size	= sizeof(struct ipou_msg_hdr),
		.has_session	= 0
	},
	[IPOU_MSG_GOODBYE] = {
		.name		= "GOODBYE",
		.cksize		= NULL,
		.min_size	= sizeof(struct ipou_msg_hdr),
		.has_session	= 1
	},
	[IPOU_MSG_BAD_PROTO] = {
		.name		= "BAD PROTOCOL VERSION",
		.cksize		= NULL,
		.min_size	= sizeof(struct ipou_msg_bad_proto),
		.has_session	= 0
	},
	[IPOU_MSG_PING] = {
		.name		= "PING",
		.cksize		= NULL,
		.min_size	= sizeof(struct ipou_msg_hdr),
		.has_session	= 1
	},
	[IPOU_MSG_PONG] = {
		.name		= "PONG",
		.cksize		= NULL,
		.min_size	= sizeof(struct ipou_msg_hdr),
		.has_session	= 1
	}
};

static void ipou_socket(void)
{
	int err;

	if ((ipou_socket_fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		IPOU_PFATAL("Failed to create server socket");

	err = setsockopt(ipou_socket_fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER,
			 &ipou_pmtudisc_do, sizeof ipou_pmtudisc_do);
	if (err)
		IPOU_PFATAL("setsockopt(IPV6_MTU_DISCOVER)");
}

void ipou_server_socket(void)
{
	char buf[IPOU_SOCK_ADDRSTRLEN];

	ipou_socket();

	if (bind(ipou_socket_fd, &ipou_server.sa, sizeof ipou_server.sin6)
			< 0) {
		IPOU_FATAL("Failed to bind server socket to %s: %m",
			   ipou_sock_ntop(&ipou_server.sin6, buf));
	}
}

void ipou_client_socket(void)
{
	static const struct timeval timeout = {
		.tv_sec		= 30,
		.tv_usec	= 0
	};

	char buf[IPOU_SOCK_ADDRSTRLEN];
	int err;

	ipou_socket();

	if (connect(ipou_socket_fd, &ipou_server.sa, sizeof ipou_server.sin6)
			< 0) {
		IPOU_FATAL("Failed to connect client socket to %s: %m",
			   ipou_sock_ntop(&ipou_server.sin6, buf));
	}

	err = setsockopt(ipou_socket_fd, SOL_SOCKET, SO_RCVTIMEO,
			 &timeout, sizeof timeout);
	if (err)
		IPOU_PFATAL("setsockopt(SO_RCVTIMEO)");
}

static const char *ipou_msg_size_err(size_t bytes)
{
	if (ipou_msg_types[ipou_buf.hdr.msg_type].cksize == NULL) {

		if (bytes != ipou_msg_types[ipou_buf.hdr.msg_type].min_size)
			return "incorrect size";
	}
	else {
		return ipou_msg_types[ipou_buf.hdr.msg_type].cksize(bytes);
	}

	return NULL;
}

int ipou_recvmsg(union ipou_sockaddr *const src, const int flags)
{
	char addrbuf[IPOU_SOCK_ADDRSTRLEN];
	union ipou_sockaddr addr;
	socklen_t addrlen;
	const char *err;
	ssize_t bytes;

	addrlen = sizeof addr;

	bytes = recvfrom(ipou_socket_fd, &ipou_buf, sizeof ipou_buf,
			 MSG_TRUNC | flags, &addr.sa, &addrlen);
	if (bytes < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)  // EINPROGRESS?
			return 0;
		IPOU_PFATAL("recvfrom");
	}

	IPOU_ASSERT(addr.sa.sa_family == AF_INET6);

	if ((size_t)bytes > sizeof ipou_buf) {
		IPOU_ERR("Packet from %s too large; ignoring",
			 ipou_sock_ntop(&addr.sin6, addrbuf));
		return -1;
	}

	if ((size_t)bytes < sizeof ipou_buf.hdr) {
		IPOU_ERR("Packet from %s too small; ignoring",
			 ipou_sock_ntop(&addr.sin6, addrbuf));
		return -1;
	}

	if (ipou_buf.hdr.msg_type > IPOU_MSG_MAX) {
		IPOU_ERR("Invalid message type (%hhu) from %s; ignoring",
			 ipou_buf.hdr.msg_type,
			 ipou_sock_ntop(&addr.sin6, addrbuf));
		return -1;
	}

	if ((err = ipou_msg_size_err(bytes)) != NULL) {
		IPOU_ERR("Invalid %s message from %s: %s; ignoring",
			 ipou_msg_types[ipou_buf.hdr.msg_type].name,
			 ipou_sock_ntop(&addr.sin6, addrbuf), err);
		return -1;
	}

	if (ipou_buf.hdr.msg_type >= IPOU_MSG_HELLO) {
		IPOU_DEBUG("Received %s message from %s",
			   ipou_msg_types[ipou_buf.hdr.msg_type].name,
			   ipou_sock_ntop(&addr.sin6, addrbuf));
	}
	else {
		IPOU_PKTLOG("Received %s message from %s",
			    ipou_msg_types[ipou_buf.hdr.msg_type].name,
			    ipou_sock_ntop(&addr.sin6, addrbuf));
	}

	if (src != NULL)
		src->sin6 = addr.sin6;

	return 1;
}

void ipou_sendmsg(const union ipou_sockaddr *const dst, const size_t size)
{
	char addrbuf[IPOU_SOCK_ADDRSTRLEN];
	ssize_t sent;

	sent = sendto(ipou_socket_fd, &ipou_buf, size, 0,
		      &dst->sa, (dst != NULL) ? sizeof dst->sin6 : 0);
	if (sent < 0)
		IPOU_PFATAL("sendto");

	if ((size_t)sent != size)
		IPOU_FATAL("Sent %zd bytes; expected to send %zu", sent, size);

	if (ipou_buf.hdr.msg_type >= IPOU_MSG_HELLO) {
		IPOU_DEBUG("Sent %s message to %s",
			   ipou_msg_types[ipou_buf.hdr.msg_type].name,
			   (dst == NULL) ? "server" :
				ipou_sock_ntop(&dst->sin6, addrbuf));
	}
	else {
		IPOU_PKTLOG("Sent %s message to %s",
			    ipou_msg_types[ipou_buf.hdr.msg_type].name,
			    (dst == NULL) ? "server" :
				ipou_sock_ntop(&dst->sin6, addrbuf));
	}

}

static const char *ipou_ck_pkt4_size(const size_t msg_size)
{
	if (msg_size != sizeof ipou_buf.pkt.hdr + ipou_pkt4_size())
		return "incorrect size";

	return NULL;
}

static const char *ipou_ck_pkt6_size(const size_t msg_size)
{
	if (msg_size != sizeof ipou_buf.pkt.hdr + ipou_pkt6_size())
		return "incorrect size";

	return NULL;
}

static const char *ipou_ck_ready_size(const size_t msg_size)
{
	if (msg_size != ipou_max_msg_size)
		return "incorrect size";

	return NULL;
}

static const char *ipou_ck_welcome_size(const size_t msg_size)
{
	size_t size;

	if (msg_size != ntohs(ipou_buf.welcome.max_msg_size))
		return "incorrect size";

	size = sizeof ipou_buf.welcome
		+ ipou_buf.welcome.num_routes * sizeof(union ipou_msg_route);

	if (size > msg_size)
		return "too many routes";

	return NULL;
}
