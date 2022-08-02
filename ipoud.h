#ifndef IPOU_IPOUD_H_INCLUDED
#define IPOU_IPOUD_H_INCLUDED

#define _GNU_SOURCE

#include <inttypes.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <syslog.h>

#include "iputil.h"

/* Protocol version */
#define IPOU_MK_PROTOVER(yr, mo, day, subver)			\
	IPOU_HTONL(	(((uint32_t)yr & 0xffff) << 16)		\
			| (((uint32_t)mo & 0x0f) << 12)		\
			| (((uint32_t)day & 0x1f) << 7)		\
			| ((uint32_t)subver & 0x7f)		\
	)

/* Default values */
#define IPOU_DEF_CFG_FILE	"/etc/ipoud.conf"
#define IPOU_DEF_UDP_PORT	4542
#define IPOU_DEF_MAX_CLIENTS	16

/* "Magic numbers" */
#define IPOU_BUF_SIZE		2000
#define IPOU_SOCK_ADDRSTRLEN	(INET6_ADDRSTRLEN + 8)  /* [<addr>]:65535 */
#define IPOU_PROTOVER_STRLEN	(sizeof "65535.255.255.255.255")
#define IPOU_ID_NONE		255
#define IPOU_MAX_ROUTES		20	/* max # of routes of each type */
#define IPOU_MIN_PATH_MTU	608	/* min IPv4 MTU over IPv4 tunnel */
#define IPOU_MAX_PATH_MTU	1500
#define IPOU_PROTO_VER		IPOU_MK_PROTOVER(2022, 7, 24, 2)

/* Client exit reasons */
#define IPOU_CLIENT_EXIT_GOODBYE	((sig_atomic_t)-1)
#define IPOU_CLIENT_EXIT_RENEG		((sig_atomic_t)-2)  /* reneg failed */
#define IPOU_CLIENT_EXIT_TIMEOUT	((sig_atomic_t)-3)
_Static_assert(IPOU_CLIENT_EXIT_TIMEOUT < 0
			&& IPOU_CLIENT_EXIT_TIMEOUT >= SIG_ATOMIC_MIN,
	       "IPOU_EXIT_TIMEOUT is not a valid sig_atomic_t");

/* Used to calculate maximum message size from path MTU */
#define IPOU_IPUDP_HDR_SIZE4	28  /* 20-byte IPv4 hdr + 8-byte UDP hdr */
#define IPOU_IPUDP_HDR_SIZE6	48  /* 40-byte IPv6 hdr + 8-byte UDP hdr */


/*
 *
 *	IPoU Messages
 *
 */

enum ipou_msg_type {
	IPOU_MSG_PACKET4 = 0,
	IPOU_MSG_PACKET6,
	IPOU_MSG_HELLO,
	IPOU_MSG_WELCOME,
	IPOU_MSG_BUSY,
	IPOU_MSG_READY,
	IPOU_MSG_BAD_SESSION,
	IPOU_MSG_GOODBYE,
	IPOU_MSG_BAD_PROTO,
	IPOU_MSG_PING,
	IPOU_MSG_PONG,
	/* *** Make sure to keep IPOU_MSG_MAX updated! *** */
	IPOU_MSG_MAX = IPOU_MSG_PONG
}
__attribute__((packed));
_Static_assert(sizeof(enum ipou_msg_type) == 1, "ipou_msg_type size");

struct ipou_msg_type_t {
	const char		*name;
	const char		*(*cksize)(size_t msg_size);
	size_t			min_size;
	_Bool			has_session;
};

struct ipou_msg_route4 {
	uint8_t			family;
	uint8_t			pfx_len;
	uint8_t			__padding[2];
	struct in_addr		dest;
};
_Static_assert(sizeof(struct ipou_msg_route4) == 8, "ipou_msg_route4 size");
_Static_assert(4 % _Alignof(struct ipou_msg_route4) == 0,
	       "ipou_msg_route4 alignment");

struct ipou_msg_route6 {
	uint8_t			family;
	uint8_t			pfx_len;
	uint8_t			__padding[2];
	struct in6_addr		dest;
};
_Static_assert(sizeof(struct ipou_msg_route6) == 20, "ipou_msg_route6 size");
_Static_assert(4 % _Alignof(struct ipou_msg_route6) == 0,
	       "ipou_msg_route6 alignment");

union ipou_msg_route {
	uint8_t			family;
	struct ipou_msg_route6	r6;
	struct ipou_msg_route4	r4[2];
};
_Static_assert(sizeof(union ipou_msg_route) == 20, "ipou_msg_route size");
_Static_assert(4 % _Alignof(union ipou_msg_route) == 0,
	       "ipou_msg_route alignment");

struct ipou_msg_hdr {
	enum ipou_msg_type	msg_type;
	uint8_t			client_id;
	uint16_t		session_id;  /* network byte order */
	uint8_t			data[0];
};
_Static_assert(sizeof(struct ipou_msg_hdr) == 4, "ipou_msg_hdr size");

struct ipou_msg_hello {
	struct ipou_msg_hdr	hdr;
	uint32_t		proto_ver;  /* network byte order */
};
_Static_assert(sizeof(struct ipou_msg_hello) == 8, "ipou_msg_hello size");

struct ipou_msg_bad_proto{
	struct ipou_msg_hdr	hdr;
	uint32_t		proto_ver;  /* network byte order */
};
_Static_assert(sizeof(struct ipou_msg_bad_proto) == 8,
	       "ipou_msg_bad_proto size");

struct ipou_msg_welcome {
	struct ipou_msg_hdr	hdr;
	struct in6_addr		addr6;
	struct in6_addr		gateway6;  /* server's TUN address */
	struct in_addr		addr4;
	struct in_addr		gateway4;  /* servers TUN address */
	uint16_t		max_msg_size;  /* network byte order */
	uint8_t			pfx_len6;
	uint8_t			pfx_len4;
	uint8_t			num_routes;
	uint8_t			__zeroes[3];
	union ipou_msg_route	routes[0];
};
_Static_assert(sizeof(struct ipou_msg_welcome) == 52, "ipou_msg_welcome size");

struct ipou_msg_pkt {
	struct ipou_msg_hdr		hdr;
	union {
		struct ipou_ip_hdr	ip;
		struct ipou_ip4_hdr	ip4;
		struct ipou_ip6_hdr	ip6;
	};
};
_Static_assert(offsetof(struct ipou_msg_pkt, ip) == sizeof(struct ipou_msg_hdr),
	       "ipou_msg_pkt padding");

/*
 *
 *	Other types
 *
 */

enum ipou_pkt_err {
	IPOU_PKT_OK,
	IPOU_PKT_SRC_NOT_LOCL,
	IPOU_PKT_DST_IS_BCAST,
	IPOU_PKT_DST_IS_MCAST,
	IPOU_PKT_DST_IS_LINK,
	IPOU_PKT_DST_IS_LOOP,
	IPOU_PKT_DST_NOT_SRVR,
};

union ipou_sockaddr {
	struct sockaddr		sa;
	struct sockaddr_in	sin;
	struct sockaddr_in6	sin6;
};

enum ipou_op_mode {
	IPOU_MODE_UNSET,
	IPOU_MODE_SERVER,
	IPOU_MODE_CLIENT
};

struct ipou_cfg_route4 {
	struct ipou_cfg_route4	*next;
	struct in_addr		dest;
	uint8_t			pfx_len;
	uint8_t			count;
};

struct ipou_cfg_route6 {
	struct ipou_cfg_route6	*next;
	struct in6_addr		dest;
	uint8_t			pfx_len;
	uint8_t			count;
};

struct ipou_buf_icmp4 {
	struct ipou_msg_hdr		__unused;
	struct ipou_icmp_pkt4		hdrs;
	union {
		struct ipou_ip4_hdr	orig;
		uint8_t			data[548];
	};
};
_Static_assert(sizeof(struct ipou_buf_icmp4) == 580, "ipou_buf_icmp4 size");

struct ipou_buf_icmp6 {
	struct ipou_msg_hdr		__unused;
	struct ipou_icmp_pkt6		hdrs;
	union {
		struct ipou_ip6_hdr	orig;
		uint8_t			data[1232];
	};
};
_Static_assert(sizeof(struct ipou_buf_icmp6) == 1284, "ipou_buf_icmp6 size");

union ipou_buf_t {
	struct ipou_msg_hdr		hdr;
	struct ipou_msg_hello		hello;
	struct ipou_msg_bad_proto	bad_proto;
	struct ipou_msg_welcome		welcome;
	struct ipou_msg_pkt		pkt;
	struct ipou_buf_icmp4		icmp4;
	struct ipou_buf_icmp6		icmp6;
	uint8_t				raw[IPOU_BUF_SIZE];
	uint16_t			raw16[IPOU_BUF_SIZE / 2];
	uint32_t			raw32[IPOU_BUF_SIZE / 4];
};
_Static_assert(IPOU_BUF_SIZE % sizeof(uint32_t) == 0,
	       "IPOU_BUF_SIZE not multiple of 4");


/*
 *
 *	Global variables
 *
 */

extern const char *const ipou_err_msgs[];
extern const struct ipou_msg_type_t ipou_msg_types[];
extern union ipou_buf_t ipou_buf;
extern int ipou_tun_fd;
extern int ipou_tun_index;
extern int ipou_socket_fd;
extern volatile sig_atomic_t ipou_exit_flag;


/* Configuration settings */
extern char ipou_tun_name[IFNAMSIZ];
extern _Bool ipou_use_syslog;
extern _Bool ipou_debug;
extern _Bool ipou_log_pkts;
extern enum ipou_op_mode ipou_mode;
extern int ipou_peer_timeout;

extern union ipou_sockaddr ipou_server;
extern struct in6_addr ipou_tun_addr6;
extern uint8_t ipou_tun_pfx6;
extern struct in_addr ipou_tun_addr4;
extern uint8_t ipou_tun_pfx4;
extern struct ipou_cfg_route4 *ipou_cfg_routes4;
extern struct ipou_cfg_route6 *ipou_cfg_routes6;
extern uint8_t ipou_max_clients;
extern struct in_addr ipou_pool4;
extern struct in6_addr ipou_pool6;
extern struct in_addr ipou_tun_netmask4;
extern struct in_addr ipou_tun_netaddr4;
extern struct in_addr ipou_gateway4;
extern struct in6_addr ipou_tun_netmask6;
extern struct in6_addr ipou_tun_netaddr6;
extern struct in6_addr ipou_gateway6;
extern uint8_t ipou_hello_routes;
extern uint16_t ipou_max_msg_size;


/*
 *
 *	Inline functions
 *
 */


/* Return the TUN MTU, calculated from the maximum message size */
__attribute__((always_inline))
inline uint16_t ipou_tun_mtu(void)
{
	return ipou_max_msg_size - sizeof(struct ipou_msg_hdr);
}

/* Calculate the size of the IPv4 packet in the buffer, based on its header */
__attribute__((always_inline))
inline size_t ipou_pkt4_size(void)
{
	return ntohs(ipou_buf.pkt.ip4.total_len);
}

/* Calculate the size of the IPv6 packet in the buffer, based on its header */
__attribute__((always_inline))
inline size_t ipou_pkt6_size(void)
{
	return ntohs(ipou_buf.pkt.ip6.data_len) + sizeof ipou_buf.pkt.ip6;
}

/* Calculate the size of the IPv4 or IPv6 packet in the buffer (-1 on error) */
__attribute__((always_inline))
inline ssize_t ipou_pkt_size(void)
{
	if (ipou_buf.pkt.ip.version == 4)
		return ipou_pkt4_size();
	else if (ipou_buf.pkt.ip.version == 6)
		return ipou_pkt6_size();
	else
		return -1;
}

__attribute__((always_inline))
inline const char *ipou_fmt_protover(uint32_t ver, char *restrict const buf)
{
	ver = ntohl(ver);

	sprintf(buf, "%" PRIu32 ".%" PRIu32 ".%" PRIu32 ".%h" PRIu32,
		(ver & 0xffff0000U) >> 16, (ver & 0x0000f000U) >> 12,
		(ver & 0x00000f80U) >> 7, ver & 0x0000007fU);

	return buf;
}


/*
 *
 *	Other functions (and helper macros)
 *
 */

/* icmp.c */
void ipou_icmp_init(void);
void ipou_send_dest_unreach6(const char *dst);
void ipou_send_dest_unreach4(const char *dst);


/* netlink.c */
void ipou_netlink_init(void);
void ipou_netlink_cleanup(void);
void ipou_set_addrgenmode(void);
void ipou_add_route6(const struct ipou_msg_route6 *route,
		     const struct in6_addr *gateway);
void ipou_add_route4(const struct ipou_msg_route4 *route,
		     struct in_addr gateway);

/* message.c */
void ipou_server_socket(void);
void ipou_client_socket(void);
int ipou_recvmsg(union ipou_sockaddr *src, int flags);
void ipou_sendmsg(const union ipou_sockaddr *dst, size_t size);

/* tun.c */
void ipou_tun_setup(void);

/* packet.c */
ssize_t ipou_recvpkt(char *restrict srcbuf, char *restrict dstbuf);
enum ipou_pkt_err ipou_pkt_client_err4(struct in_addr client_tun,
				       struct in_addr server_tun);
enum ipou_pkt_err ipou_pkt_client_err6(
				const struct in6_addr *restrict client_tun,
				const struct in6_addr *restrict server_tun);

/* config.c */
void ipou_get_config(char **argv);

/* server.c */
void ipou_server_setup(void);
void ipou_server_process(const struct pollfd *pfds);
void ipou_server_shutdown(void);

/* client.c */
void ipou_client_setup(void);
void ipou_client_process(const struct pollfd *pfds);
void ipou_client_shutdown(void);

/* util.c */
__attribute__((format(printf, 2, 3)))
void ipou_log(int level, const char *restrict format, ...);
void *ipou_zalloc(size_t size, const char *restrict file, int line);
#define IPOU_ZALLOC(size)	ipou_zalloc((size), __FILE__, __LINE__)
char *ipou_strdup(const char *restrict s, const char *restrict file, int line);
#define IPOU_STRDUP(s)		ipou_strdup((s), __FILE__, __LINE__)
__attribute__((format(printf, 3, 4)))
char *ipou_asprintf(const char *restrict file, int line,
		    const char *restrict format, ...);
#define IPOU_ASPRINTF(fmt, ...)	\
			ipou_asprintf(__FILE__, __LINE__, (fmt), ##__VA_ARGS__)
const char *ipou_ntop(const struct in6_addr *addr, char *restrict dst);
const char *ipou_sock_ntop(const struct sockaddr_in6 *addr, char *restrict dst);


/*
 *
 *	Logging macros
 *
 */

/* Preprocessor dance to "stringify" an expanded macro value (e.g. __LINE__) */
#define IPOU_STR_RAW(x)		#x
#define	IPOU_STR(x)		IPOU_STR_RAW(x)

/* Expands to a message preamble fragment which specifies file & line # */
#define IPOU_LOCATION		__FILE__ ":" IPOU_STR(__LINE__) ": "

/* Expands to syslog priority & full message preamble */
#define IPOU_LOG_HDR(lvl)	LOG_ ## lvl, #lvl ": " IPOU_LOCATION

/* Debug messages are logged at LOG_INFO priority to avoid syslog filtering */
#define IPOU_DEBUG_HDR		LOG_INFO, "DEBUG: " IPOU_LOCATION
#define IPOU_DEBUG(fmt, ...)						\
	do {								\
		if (ipou_debug)						\
			ipou_log(IPOU_DEBUG_HDR fmt, ##__VA_ARGS__);	\
	}								\
	while (0)

/* Packet logging */
#define IPOU_PKTLOG(fmt, ...)						\
	do {								\
		if (ipou_log_pkts)					\
			ipou_log(IPOU_DEBUG_HDR fmt, ##__VA_ARGS__);	\
	}								\
	while(0)

/* Print or log a message of the specified priority */
#define IPOU_INFO(fmt, ...)	ipou_log(IPOU_LOG_HDR(INFO) fmt, ##__VA_ARGS__)
#define IPOU_NOTICE(fmt, ...)	\
			ipou_log(IPOU_LOG_HDR(NOTICE) fmt, ##__VA_ARGS__)
#define IPOU_WARNING(fmt, ...)	\
			ipou_log(IPOU_LOG_HDR(WARNING) fmt, ##__VA_ARGS__)
#define IPOU_ERR(fmt, ...)	ipou_log(IPOU_LOG_HDR(ERR) fmt, ##__VA_ARGS__)
#define IPOU_CRIT(fmt, ...)	ipou_log(IPOU_LOG_HDR(CRIT) fmt, ##__VA_ARGS__)
#define IPOU_ALERT(fmt, ...)	ipou_log(IPOU_LOG_HDR(ALERT) fmt, ##__VA_ARGS__)
#define IPOU_EMERG(fmt, ...)	ipou_log(IPOU_LOG_HDR(EMERG) fmt, ##__VA_ARGS__)

/* Print or log an unexpected internal error and abort */
#define IPOU_ABORT(...)		\
			do { IPOU_CRIT(__VA_ARGS__); abort(); } while (0)

#define IPOU_ASSERT(expr)						\
	do {								\
		if (!(expr))						\
			IPOU_ABORT("Assertion failed: " #expr);		\
	} while (0)

/* Print a fatal error and exit immediately */
#define IPOU_FATAL(...)							\
	do {								\
		IPOU_ERR(__VA_ARGS__);					\
		exit(EXIT_FAILURE);					\
	} while (0)

#define IPOU_PFATAL(msg)		IPOU_FATAL("%s: %m", msg)


#endif  /* IPOU_IPOUD_H_INCLUDED */
