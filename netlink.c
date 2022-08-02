/*
 *
 *	netlink.c
 *
 *	Netlink stuff
 *
 */

#include "ipoud.h"

#include <arpa/inet.h>
#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>
#include <time.h>

static struct mnl_socket *ipou_mnl = NULL;
static uint8_t *ipou_nlmsgbuf = NULL;
static uint32_t ipou_nlmsgseq;
static unsigned int ipou_nlportid;

void ipou_netlink_init(void)
{
	ipou_nlmsgbuf = IPOU_ZALLOC(MNL_SOCKET_BUFFER_SIZE);
	ipou_nlmsgseq = time(NULL);

	if ((ipou_mnl = mnl_socket_open(NETLINK_ROUTE)) == NULL)
		IPOU_PFATAL("Failed to create NETLINK_ROUTE socket");

	if (mnl_socket_bind(ipou_mnl, 0, MNL_SOCKET_AUTOPID) != 0)
		IPOU_PFATAL("Failed to bind NETLINK_ROUTE socket");

	ipou_nlportid = mnl_socket_get_portid(ipou_mnl);
}

void ipou_netlink_cleanup(void)
{
	if (mnl_socket_close(ipou_mnl) != 0)
		IPOU_PFATAL("Failed to close NETLINK_ROUTE socket");

	free(ipou_nlmsgbuf);
	ipou_nlmsgbuf = NULL;
	ipou_mnl = NULL;
}

static struct nlmsghdr *ipou_nl_newmsg(const uint16_t type, uint16_t flags)
{
	struct nlmsghdr *nlh;

	nlh = mnl_nlmsg_put_header(ipou_nlmsgbuf);
	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = flags;
	nlh->nlmsg_seq = ++ipou_nlmsgseq;

	return nlh;
}

static ssize_t ipou_nl_sendmsg(const struct nlmsghdr *const nlh)
{
	ssize_t result;

	if (mnl_socket_sendto(ipou_mnl, nlh, nlh->nlmsg_len) < 0)
		IPOU_PFATAL("Failed to send RTNETLINK message");

	result = mnl_socket_recvfrom(ipou_mnl, ipou_nlmsgbuf,
				     MNL_SOCKET_BUFFER_SIZE);
	if (result < 0)
		IPOU_FATAL("Failed to receive RTNETLINK message");

	result = mnl_cb_run(ipou_nlmsgbuf, result, ipou_nlmsgseq,
			    ipou_nlportid, NULL, NULL);

	return result;
}

void ipou_add_route4(const struct ipou_msg_route4 *const route,
		     const struct in_addr gateway)
{
	char dst[INET_ADDRSTRLEN], gw[INET_ADDRSTRLEN];
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;

	nlh = ipou_nl_newmsg(RTM_NEWROUTE,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE);

	rtm = mnl_nlmsg_put_extra_header(nlh, sizeof *rtm);
	rtm->rtm_family = AF_INET;
	rtm->rtm_dst_len = route->pfx_len;
	rtm->rtm_table = RT_TABLE_MAIN;
	rtm->rtm_protocol = RTPROT_STATIC;
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	rtm->rtm_type = RTN_UNICAST;

	mnl_attr_put_u32(nlh, RTA_DST, route->dest.s_addr);
	mnl_attr_put_u32(nlh, RTA_GATEWAY, gateway.s_addr);
	mnl_attr_put_u32(nlh, RTA_OIF, ipou_tun_index);

	if (ipou_nl_sendmsg(nlh) < 0)
		IPOU_PFATAL("Failed to add IPv4 route");

	IPOU_DEBUG("Added IPv4 route: %s/%hhu via %s",
		   inet_ntop(AF_INET, &route->dest, dst, sizeof dst),
		   route->pfx_len, inet_ntop(AF_INET, &gateway, gw, sizeof gw));
}

void ipou_add_route6(const struct ipou_msg_route6 *const route,
		     const struct in6_addr *const gateway)
{
	char dst[INET6_ADDRSTRLEN], gw[INET6_ADDRSTRLEN];
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;

	nlh = ipou_nl_newmsg(RTM_NEWROUTE,
			NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE);

	rtm = mnl_nlmsg_put_extra_header(nlh, sizeof *rtm);
	rtm->rtm_family = AF_INET6;
	rtm->rtm_dst_len = route->pfx_len;
	rtm->rtm_table = RT_TABLE_MAIN;
	rtm->rtm_protocol = RTPROT_STATIC;
	rtm->rtm_scope = RT_SCOPE_UNIVERSE;
	rtm->rtm_type = RTN_UNICAST;

	mnl_attr_put(nlh, RTA_DST, sizeof route->dest, &route->dest);
	mnl_attr_put(nlh, RTA_GATEWAY, sizeof *gateway, gateway);
	mnl_attr_put_u32(nlh, RTA_OIF, ipou_tun_index);

	if (ipou_nl_sendmsg(nlh) < 0)
		IPOU_PFATAL("Failed to add IPv6 route");

	IPOU_DEBUG("Added IPv6 route: %s/%hhu via %s",
		   inet_ntop(AF_INET6, &route->dest, dst, sizeof dst),
		   route->pfx_len,
		   inet_ntop(AF_INET6, gateway, gw, sizeof gw));
}

void ipou_set_addrgenmode(void)
{
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct nlattr *af_attr, *in6_attr;

	nlh = ipou_nl_newmsg(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK);

	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof *ifi);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_type = 0 /* ARPHRD_NETROM? */;
	ifi->ifi_index = ipou_tun_index;

	af_attr = mnl_attr_nest_start(nlh, IFLA_AF_SPEC);
	in6_attr = mnl_attr_nest_start(nlh, AF_INET6);
	mnl_attr_put_u8(nlh, IFLA_INET6_ADDR_GEN_MODE, IN6_ADDR_GEN_MODE_NONE);
	mnl_attr_nest_end(nlh, in6_attr);
	mnl_attr_nest_end(nlh, af_attr);

	if (ipou_nl_sendmsg(nlh) < 0)
		IPOU_PFATAL("Failed to disable IPv6 address generation");
}
