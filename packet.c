/*
 *
 *	packet.c
 *
 *	Role-independent IP packet processing
 *
 */

#include "ipoud.h"

#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>

const char *const ipou_pkt_errs[] = {
	[IPOU_PKT_OK]		= NULL,
	[IPOU_PKT_SRC_NOT_LOCL]	= "source is not local TUN address",
	[IPOU_PKT_DST_IS_BCAST]	= "destination is broadcast address",
	[IPOU_PKT_DST_IS_MCAST]	= "destination is multicast address",
	[IPOU_PKT_DST_IS_LINK]	= "destination is link-local address",
	[IPOU_PKT_DST_IS_LOOP]	= "destination is loopback address",
	[IPOU_PKT_DST_NOT_SRVR]	= "destination is not server TUN address"
};

ssize_t ipou_recvpkt(char *restrict const srcbuf, char *restrict const dstbuf)
{
	ssize_t bytes;

	bytes = read(ipou_tun_fd, ipou_buf.hdr.data,
		     IPOU_BUF_SIZE - sizeof ipou_buf.hdr);
	if (bytes < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		IPOU_PFATAL("read");
	}

	if ((size_t)bytes < sizeof(struct ipou_ip4_hdr)) {
		IPOU_ERR("Packet too small (%zd bytes); ignoring", bytes);
		return -1;
	}

	if (ipou_buf.pkt.ip.version == 4) {

		if ((size_t)bytes != ipou_pkt4_size()) {
			IPOU_ERR("Incorrect IPv4 packet size; ignoring");
			return -1;
		}

		if (ipou_log_pkts) {
			inet_ntop(AF_INET, &ipou_buf.pkt.ip4.source_addr,
				  srcbuf, INET6_ADDRSTRLEN);
			inet_ntop(AF_INET, &ipou_buf.pkt.ip4.dest_addr,
				  dstbuf, INET6_ADDRSTRLEN);
		}
	}
	else if (ipou_buf.pkt.ip.version == 6) {

		if ((size_t)bytes < sizeof(struct ipou_ip6_hdr)) {
			IPOU_ERR("Packet too small (%zd bytes); ignoring",
				 bytes);
			return -1;
		}

		if ((size_t)bytes != ipou_pkt6_size()) {
			IPOU_ERR("Incorrect IPv6 packet size; ignoring");
			return -1;
		}

		if (ipou_log_pkts) {
			inet_ntop(AF_INET6, &ipou_buf.pkt.ip6.source_addr,
				  srcbuf, INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6, &ipou_buf.pkt.ip6.dest_addr,
				  dstbuf, INET6_ADDRSTRLEN);
		}
	}
	else {
		IPOU_ERR("Invalid packet IP version (%hhu); ignoring",
			 ipou_buf.pkt.ip.version);
		return -1;
	}

	IPOU_PKTLOG("TUN packet received: %zd bytes from %s to %s",
		    bytes, srcbuf, dstbuf);

	return bytes;
}

static enum ipou_pkt_err ipou_dest_err4(void)
{
	if (ipou_is_bcast4(ipou_buf.pkt.ip4.dest_addr))
		return IPOU_PKT_DST_IS_BCAST;

	if (ipou_is_mcast4(ipou_buf.pkt.ip4.dest_addr))
		return IPOU_PKT_DST_IS_MCAST;

	if (ipou_is_linklocal4(ipou_buf.pkt.ip4.dest_addr))
		return IPOU_PKT_DST_IS_LINK;

	if (ipou_is_loopback4(ipou_buf.pkt.ip4.dest_addr))
		return IPOU_PKT_DST_IS_LOOP;

	return IPOU_PKT_OK;
}

enum ipou_pkt_err ipou_pkt_client_err4(const struct in_addr client_tun,
				       const struct in_addr server_tun)
{
	enum ipou_pkt_err err;

	/*
	 * Client shouldn't be routing anything over the tunnel, so the source
	 * address should always be the client's TUN address
	 */
	if (ipou_buf.pkt.ip4.source_addr.s_addr != client_tun.s_addr)
		return IPOU_PKT_SRC_NOT_LOCL;

	/* Check for non-forwardable destination address (multicast, etc.) */
	if ((err = ipou_dest_err4()) != IPOU_PKT_OK)
		return err;

	/*
	 * Client can't send to any address within the TUN subnet
	 * except the server
	 */
	if (ipou_in_net4(ipou_buf.pkt.ip4.dest_addr,
				ipou_tun_netaddr4, ipou_tun_netmask4)
			&& ipou_buf.pkt.ip4.dest_addr.s_addr
				!=  server_tun.s_addr) {

		return IPOU_PKT_DST_NOT_SRVR;
		// TODO - client should send ICMP
	}

	return IPOU_PKT_OK;
}

static enum ipou_pkt_err ipou_dest_err6(void)
{
	if (IN6_IS_ADDR_MULTICAST(&ipou_buf.pkt.ip6.dest_addr))
		return IPOU_PKT_DST_IS_MCAST;

	if (IN6_IS_ADDR_LINKLOCAL(&ipou_buf.pkt.ip6.dest_addr))
		return IPOU_PKT_DST_IS_LINK;

	if (IN6_IS_ADDR_LOOPBACK(&ipou_buf.pkt.ip6.dest_addr))
		return IPOU_PKT_DST_IS_LOOP;

	return IPOU_PKT_OK;
}

enum ipou_pkt_err ipou_pkt_client_err6(
			const struct in6_addr *restrict const client_tun,
			const struct in6_addr *restrict const server_tun)
{
	enum ipou_pkt_err err;

	/*
	 * Client shouldn't be routing anything over the tunnel, so the source
	 * address should always be the client's TUN address
	 */
	if (memcmp(&ipou_buf.pkt.ip6.source_addr, client_tun, 16) != 0)
		return IPOU_PKT_SRC_NOT_LOCL;

	/* Check for non-forwardable destination address (multicast, etc.) */
	if ((err = ipou_dest_err6()) != IPOU_PKT_OK)
		return err;

	/*
	 * Client can't send to any address within the TUN subnet
	 * except the server
	 */
	if (ipou_in_net6(&ipou_buf.pkt.ip6.dest_addr, &ipou_tun_netaddr6,
							&ipou_tun_netmask6)
			&& memcmp(&ipou_buf.pkt.ip6.dest_addr,
							server_tun, 16)
				!= 0) {

		return IPOU_PKT_DST_NOT_SRVR;
		// TODO - client should send ICMP
	}

	return IPOU_PKT_OK;
}
