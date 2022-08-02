#ifndef IPOU_IPUTIL_H_INCLUDED
#define IPOU_IPUTIL_H_INCLUDED

#include <netinet/ip.h>
#include <string.h>


/*
 *
 *	Byte order stuff
 *
 */

/* Simpler byte order macros */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define IPOU_BIG_ENDIAN
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define IPOU_LITTLE_ENDIAN
#else
#error "Unknown __BYTE_ORDER__"
#endif

/* 16-bit byte swap macro */
#define IPOU_BSWAP16(x)							\
	((uint16_t)(							\
		(((uint16_t)(x) & (uint16_t)0x00ffU) << 8) |		\
		(((uint16_t)(x) & (uint16_t)0xff00U) >> 8)		\
	  ))

/* 32-bit byte swap macro */
#define IPOU_BSWAP32(x)							\
	((uint32_t)(							\
		(((uint32_t)(x) & (uint32_t)0x000000ffU) << 24) |	\
		(((uint32_t)(x) & (uint32_t)0x0000ff00U) <<  8) |	\
		(((uint32_t)(x) & (uint32_t)0x00ff0000U) >>  8) |	\
		(((uint32_t)(x) & (uint32_t)0xff000000U) >> 24)		\
	  ))

/* Macro versions of POSIX byte swapping functions for constants */
#ifdef IPOU_BIG_ENDIAN
#define	IPOU_HTONS(x)	(x)
#define IPOU_NTOHS(x)	(x)
#define IPOU_HTONL(x)	(x)
#define IPOU_NTOHL(x)	(x)
#else
#define	IPOU_HTONS(x)	IPOU_BSWAP16(x)
#define IPOU_NTOHS(x)	IPOU_BSWAP16(x)
#define IPOU_HTONL(x)	IPOU_BSWAP32(x)
#define IPOU_NTOHL(x)	IPOU_BSWAP32(x)
#endif


/*
 *
 *	Useful constants
 *
 */

#define IPOU_MCAST_ADDR4	IPOU_HTONL(0xe0000000UL)  /* 224.0.0.0/4 */
#define IPOU_MCAST_MASK4	IPOU_HTONL(0xf0000000UL)  /* 240.0.0.0 */
#define IPOU_LINKLOCAL_ADDR4	IPOU_HTONL(0xa9fe0000UL)  /* 169.254.0.0/16 */
#define IPOU_LINKLOCAL_MASK4	IPOU_HTONL(0xffff0000UL)  /* 255.255.0.0 */
#define IPOU_LOOPBACK_ADDR4	IPOU_HTONL(0x7f000000UL)  /* 127.0.0.0/8 */
#define IPOU_LOOPBACK_MASK4	IPOU_HTONL(0xff000000UL)  /* 255.0.0.0 */


/*
 *
 *	IP headers
 *
 */

struct ipou_ip_hdr {
#ifdef IPOU_BIG_ENDIAN  /* Bit field order depends on byte order */
	uint8_t		version:4;
	uint8_t		__unknown:4;
#else
	uint8_t		__unknown:4;
	uint8_t		version:4;
#endif
};
_Static_assert(sizeof(struct ipou_ip_hdr) == 1, "ipou_ip_hdr size");

struct ipou_ip4_hdr {
#ifdef IPOU_BIG_ENDIAN  /* Bit field order depends on byte order */
	uint8_t		version:4;
	uint8_t		ihl:4;
	uint8_t		dscp:6;
	uint8_t		ecn:2;
#else
	uint8_t		ihl:4;
	uint8_t		version:4;
	uint8_t		ecn:2;
	uint8_t		dscp:6;
#endif
	uint16_t	total_len;
	uint16_t	id;
	uint16_t	flags;
	uint8_t		ttl;
	uint8_t		protocol;
	uint16_t	iphdr_cksum;
	struct in_addr	source_addr;
	struct in_addr	dest_addr;
	uint8_t		data[0];
};
_Static_assert(sizeof(struct ipou_ip4_hdr) == 20, "ipou_ip4_hdr size");

struct ipou_ip6_hdr {
#ifdef IPOU_BIG_ENDIAN  /* Bit field order depends on byte order */
	uint8_t		version:4;
	uint8_t		tc_hi:4;
	uint8_t		tc_lo:4;
	uint8_t		fl_hi:4
#else
	uint8_t		tc_hi:4;
	uint8_t		version:4;
	uint8_t		fl_hi:4;
	uint8_t		tc_lo:4;
#endif
	uint16_t	fl_lo;
	uint16_t	data_len;
	uint8_t		next_hdr;
	uint8_t		hop_limit;
	struct in6_addr	source_addr;
	struct in6_addr dest_addr;
	uint8_t		data[0];
};
_Static_assert(sizeof(struct ipou_ip6_hdr) == 40, "ipou_ip6_hdr size");

struct ipou_icmp_hdr {
	uint8_t				type;
	uint8_t				code;
	uint16_t			cksum;
	union {
		uint8_t		u8[4];
		uint16_t	u16[2];
		uint32_t	u32;
	}				misc;  /* depends on type & code */
};
_Static_assert(sizeof(struct ipou_icmp_hdr) == 8, "ipou_icmp_hdr size");

struct ipou_icmp_pkt4 {
	struct ipou_ip4_hdr		ip;
	struct ipou_icmp_hdr		icmp;
	uint8_t				data[0];
};
_Static_assert(sizeof(struct ipou_icmp_pkt4) == 28, "ipou_icmp_pkt4 size");

struct ipou_icmp_pkt6 {
	struct ipou_ip6_hdr		ip;
	struct ipou_icmp_hdr		icmp;
	uint8_t				data[0];
};
_Static_assert(sizeof(struct ipou_icmp_pkt6) == 48, "ipou_icmp_pkt6 size");

/*
 *
 *	IPv4
 *
 */

/* Is the IPv4 address a multicast address (224.0.0.0/4)? */
__attribute__((always_inline))
inline _Bool ipou_is_mcast4(const struct in_addr addr)
{
	return (addr.s_addr & IPOU_MCAST_MASK4) == IPOU_MCAST_ADDR4;
}

/* Is the IPv4 address the broadbase address (255.255.255.255)? */
__attribute__((always_inline))
inline _Bool ipou_is_bcast4(const struct in_addr addr)
{
	return addr.s_addr == INADDR_BROADCAST;
}

/* Is the IPv4 address a link-local address (169.254.0.0/16)? */
__attribute__((always_inline))
inline _Bool ipou_is_linklocal4(const struct in_addr addr)
{
	return (addr.s_addr & IPOU_LINKLOCAL_MASK4) == IPOU_LINKLOCAL_ADDR4;
}

/* Is the IPv4 address a loopback address (127.0.0.0/8)? */
__attribute__((always_inline))
inline _Bool ipou_is_loopback4(const struct in_addr addr)
{
	return (addr.s_addr & IPOU_LOOPBACK_MASK4) == IPOU_LOOPBACK_ADDR4;
}

/* Return the IPv4 subnet mask, based on the prefix length */
__attribute__((always_inline))
inline struct in_addr ipou_mknetmask4(const uint8_t pfx_len)
{
	return (struct in_addr){
		.s_addr = htonl( (pfx_len == 0) ? 0
					: ~((1U << (32 - pfx_len)) - 1) )
	};
}

/* Is the IPv4 address a network address for the given host mask? */
__attribute__((always_inline))
inline _Bool ipou_is_netaddr4(const struct in_addr addr,
			      const struct in_addr netmask)
{
	return (addr.s_addr & ~netmask.s_addr) == 0;
}

/* Is the IPv4 address within the subnet defined by the net address & netmask */
__attribute__((always_inline))
inline _Bool ipou_in_net4(const struct in_addr hostaddr,
			  const struct in_addr netaddr,
			  const struct in_addr netmask)
{
	return (hostaddr.s_addr & netmask.s_addr) == netaddr.s_addr;
}

/* Is the IPv4 address a network broadcast address for the given host mask? */
__attribute__((always_inline))
inline _Bool ipou_is_netcast4(const struct in_addr addr,
			      const struct in_addr netmask)
{
	return (addr.s_addr & ~netmask.s_addr) == ~netmask.s_addr;
}

/* Return the IPv4 network address, based on the host address & subnet mask */
__attribute__((always_inline))
inline struct in_addr ipou_mknetaddr4(const struct in_addr hostaddr,
				      const struct in_addr netmask)
{
	return (struct in_addr){
		.s_addr = hostaddr.s_addr & netmask.s_addr
	};
}

/* Return the result of adding the addend to the IPv4 address */
__attribute__((always_inline))
inline struct in_addr ipou_addr_add4(const struct in_addr addr,
				     const uint8_t addend)
{
	return (struct in_addr) {
		.s_addr = htonl(ntohl(addr.s_addr) + addend)
	};
}

/* Return the result of subtracting the subtrahend from the IPv4 address */
__attribute__((always_inline))
inline struct in_addr ipou_addr_sub4(const struct in_addr addr,
				     const uint8_t subtrahend)
{
	return (struct in_addr) {
		.s_addr = htonl(ntohl(addr.s_addr) - subtrahend)
	};
}

/* Is the IPv4 address in the range base address to max address (inclusive)? */
__attribute__((always_inline))
inline _Bool ipou_in_range4(const struct in_addr addr,
			    const struct in_addr base, const struct in_addr max)
{
	const uint32_t addr_hbo = ntohl(addr.s_addr);
	return addr_hbo >= ntohl(base.s_addr) && addr_hbo <= ntohl(max.s_addr);
}

/*
 *
 *	IPv6
 *
 *	* Even on x86_64, the alignment of struct in6_addr is only 4, so IPv6
 *	  addresses can't be easily accessed as 64- or 128-bit integers.
 *
 *	* Experimentation (GCC 12.1.1 on x86_64) shows that if these functions
 *	  were static, they would be inlined at all non-zero optimization
 *	  levels (including -Os).
 *
 */

/* Ensure IPv6 address can be safely accessed as an array of uint32_t */
_Static_assert(_Alignof(struct in6_addr) % _Alignof(uint32_t) == 0,
	       "in6_addr alignment");

/* Initialize the IPv6 subnet mask, based on the prefix length */
__attribute__((always_inline))
inline void ipou_mknetmask6(uint8_t pfx_len, struct in6_addr *const netmask)
{
	struct in_addr mask;
	unsigned int i;

	for (i = 0; i < 4; ++i) {

		if (pfx_len < 32) {
			mask = ipou_mknetmask4(pfx_len);
			pfx_len = 0;
		}
		else {
			mask = (struct in_addr){ .s_addr = 0xffffffffU };
			pfx_len -= 32;
		}

		((uint32_t *)netmask)[i] = mask.s_addr;
	}
}

/* Is the IPv6 address a network address for the given host mask? */
__attribute__((always_inline))
inline _Bool ipou_is_netaddr6(const struct in6_addr *restrict const addr,
			      const struct in6_addr *restrict const netmask)
{
	int i;

	for (i = 3; i >= 0 && ((uint32_t *)netmask)[i] != 0xffffffffU; --i) {

		if ( (((uint32_t *)addr)[i] & ~((uint32_t *)netmask)[i]) != 0 )
			return 0;
	}

	/* Host portion of the address is all zeroes */
	return 1;
}

/* Is the IPv6 address within the subnet defined by the net address & netmask */
__attribute__((always_inline))
inline _Bool ipou_in_net6(const struct in6_addr *restrict const hostaddr,
			  const struct in6_addr *restrict const netaddr,
			  const struct in6_addr *restrict const netmask)
{
	unsigned int i;

	for (i = 0; i < 4 && ((uint32_t *)netmask)[i] != 0; ++i) {

		if ( (((uint32_t *)hostaddr)[i] & ((uint32_t *)netmask)[i])
						!= ((uint32_t *)netaddr)[i] )
			return 0;
	}

	/* Network portion of host address equals network address */
	return 1;
}

/* Add the addend to the IPv6 address */
__attribute__((always_inline))
inline void ipou_addr_add6(struct in6_addr *const addr, const uint8_t addend)
{
	uint32_t current, value;
	_Bool carry;
	int i;

	for (value = addend, i = 3; value > 0 && i >= 0; value = carry, --i) {
		current = ntohl(((uint32_t *)addr)[i]);
		value = current + value;
		carry = (value < current);
		((uint32_t *)addr)[i] = htonl(value);
	}
}

/* Return the result of subtracting the subtrahend from the IPv6 address */
__attribute__((always_inline))
inline void ipou_addr_sub6(struct in6_addr *const addr, const uint8_t subhend)
{
	uint32_t current, value;
	_Bool borrow;
	int i;

	for (value = subhend, i = 3; value > 0 && i >= 0; value = borrow, --i) {
		current = ntohl(((uint32_t *)addr)[i]);
		value = current - value;
		borrow = (value > current);
		((uint32_t *)addr)[i] = htonl(value);
	}
}

/* Initialize the IPv6 network address, based on the host address & netmask */
__attribute__((always_inline))
inline void ipou_mknetaddr6(const struct in6_addr *restrict const hostaddr,
			    const struct in6_addr *restrict const netmask,
			    struct in6_addr *restrict const netaddr)
{
	unsigned int i;

	for (i = 0; i < 4 ; ++i) {

		((uint32_t *)netaddr)[i] =
			((uint32_t *)hostaddr)[i] & ((uint32_t *)netmask)[i];
	}
}

/* Is the IPv6 address in the range base address to max address (inclusive)? */
__attribute__((always_inline))
inline _Bool ipou_in_range6(const struct in6_addr *restrict const addr,
			    const struct in6_addr *restrict const base,
			    const struct in6_addr *restrict const max)
{
	_Static_assert(sizeof(struct in6_addr) == 16, "in6_addr size");
	return memcmp(addr, base, 16) >= 0 && memcmp(addr, max, 16) <= 0;
}


#endif  /* IPOU_IPUTIL_H_INCLUDED */
