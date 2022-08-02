#include "ipoud.h"

#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <unistd.h>

static struct ipou_icmp_pkt6 ipou_dest_unreach6 = {
	.ip = {
		.version		= 6,
		.tc_hi			= 0,
		.tc_lo			= 0,
		.fl_hi			= 0,
		.fl_lo			= 0,
		.data_len		= 0,  /* varies */
		.next_hdr		= IPPROTO_ICMPV6,
		.hop_limit		= 64,
		.source_addr		= IN6ADDR_ANY_INIT,  /* varies */
		.dest_addr		= IN6ADDR_ANY_INIT  /* varies */
	},
	.icmp = {
		.type			= ICMP6_DST_UNREACH,
		.code			= ICMP6_DST_UNREACH_ADDR,
		.cksum			= 0,  /* varies */
		.misc			= { .u32 = 0 }
	}
};

static struct ipou_icmp_pkt4 ipou_dest_unreach4 = {
	.ip = {
		.version		= 4,
		.ihl			= 5,
		.dscp			= 0x30,  /* class selector 6 */
		.ecn			= 0,
		.total_len		= 0,  /* varies */
		.id			= 0,  /* varies */
		.flags			= 0,
		.ttl			= 64,
		.protocol		= IPPROTO_ICMP,
		.iphdr_cksum		= 0,  /* varies */
		.source_addr		= { 0 },  /* varies */
		.dest_addr		= { 0 }  /* varies */
	},
	.icmp = {
		.type			= ICMP_UNREACH,
		.code			= ICMP_UNREACH_HOST,
		.cksum			= 0,  /* varies */
		.misc			= { .u32 = 0 }
	}
};

static uint16_t ipou_cksum_add(const void *const data, const unsigned int size,
			       const uint16_t cksum)
{
	unsigned int i, dwords, bytes;
	const uint32_t *d;
	uint32_t last;
	uint64_t sum;

	IPOU_ASSERT(((uintptr_t)data & 3) == 0);

	dwords = size / sizeof(uint32_t);
	bytes = size % sizeof(uint32_t);
	d = data;
	sum = (uint16_t)~cksum;

	for (i = 0; i < dwords; ++i)
		sum += d[i];

	if (bytes > 0) {
		last = 0;
		memcpy(&last, d + i, bytes);
		sum += last;
	}

	sum = (sum & 0xffffffffU) + (sum >> 32);

	while ((sum >> 16) != 0)
		sum = (sum & 0xffffU) + (sum >> 16);

	return ~sum;
}

static uint16_t ipou_cksum(const void *const data, const unsigned int size)
{
	return ipou_cksum_add(data, size, 0);
}

static uint16_t ipou_icmp6_cksum(const unsigned int size)
{
	uint16_t sum;

	sum = ipou_buf.icmp6.hdrs.ip.data_len + IPOU_NTOHS(58);

	if (sum < IPOU_NTOHS(58))
		++sum;

	/* ICMP header immediately follows source & destination addresses */
	return ipou_cksum_add(&ipou_buf.icmp6.hdrs.ip.source_addr,
			      size + 32, sum);
}

#if 0
static uint16_t ipou_icmp6_phdr_cksum1(const struct ipou_ip6_hdr *const hdr)
{
	uint16_t sum;

	sum = hdr->data_len + IPOU_NTOHS(58);

	if (sum < IPOU_NTOHS(58))
		++sum;

	return ipou_cksum_add(&hdr->source_addr, 32, ~sum);
}

static uint16_t ipou_icmp6_phdr_cksum2(const struct ipou_ip6_hdr *const hdr)
{
	uint16_t sum;

	sum = ntohs(hdr->data_len) + 58;

	if (sum < 58)
		++sum;

	return ipou_cksum_add(&hdr->source_addr, 32, htons(~sum));
}

static uint16_t ipou_icmp6_phdr_cksum3(const struct ipou_ip6_hdr *const hdr)
{
	struct ipv6_phdr {
		struct in6_addr		source_addr;
		struct in6_addr		dest_addr;
		uint32_t		icmpv6_len;
		uint8_t			__zeroes[3];
		uint8_t			next_hdr;
	};

	_Static_assert(sizeof(struct ipv6_phdr) == 40, "ipv6_phdr size");

	struct ipv6_phdr phdr;

	memset(&phdr, 0, sizeof phdr);
	phdr.source_addr = hdr->source_addr;
	phdr.dest_addr = hdr->dest_addr;
	phdr.icmpv6_len = htonl(ntohs(hdr->data_len));
	phdr.next_hdr = 58;

	return ipou_cksum(&phdr, sizeof phdr);
}
#endif

void ipou_send_dest_unreach4(const char *const dst)
{
	unsigned int pkt_size;
	ssize_t wrote;

	/* How much of the triggering packet to include? */
	if ((pkt_size = ipou_pkt4_size()) > 548)
		pkt_size = 548;

	memmove(ipou_buf.icmp4.data, &ipou_buf.pkt.ip4, pkt_size);
	ipou_buf.icmp4.hdrs = ipou_dest_unreach4;

	pkt_size += 28;  /* total size of ICMP packet */

	ipou_buf.icmp4.hdrs.ip.total_len = htons(pkt_size);
	ipou_buf.icmp4.hdrs.ip.id = rand();
	ipou_buf.icmp4.hdrs.ip.source_addr = ipou_buf.icmp4.orig.dest_addr;
	ipou_buf.icmp4.hdrs.ip.dest_addr = ipou_buf.icmp4.orig.source_addr;
	ipou_buf.icmp4.hdrs.ip.iphdr_cksum =
			ipou_cksum(&ipou_buf.icmp4.hdrs.ip, 20);
	ipou_buf.icmp4.hdrs.icmp.cksum =
			ipou_cksum(&ipou_buf.icmp4.hdrs.icmp, pkt_size - 20);

	if ((wrote = write(ipou_tun_fd, ipou_buf.hdr.data, pkt_size)) < 0)
		IPOU_PFATAL("write");

	IPOU_ASSERT((size_t)wrote == pkt_size);

	IPOU_PKTLOG("Sent ICMP destination unreachable to %s", dst);
}

void ipou_send_dest_unreach6(const char *const dst)
{
	unsigned int size;
	ssize_t wrote;

	/* How much of the triggering packet to include? */
	if ((size = ipou_pkt6_size()) > 1232)
		size = 1232;

	memmove(ipou_buf.icmp6.data, &ipou_buf.pkt.ip6, size);
	ipou_buf.icmp6.hdrs = ipou_dest_unreach6;

	size += 8;  /* ICMP header & data */

	ipou_buf.icmp6.hdrs.ip.data_len = htons(size);
	ipou_buf.icmp6.hdrs.ip.dest_addr = ipou_buf.icmp6.orig.source_addr;
	ipou_buf.icmp6.hdrs.icmp.cksum = ipou_icmp6_cksum(size);

	size += 40;  /* Total size of ICMP packet */

	if ((wrote = write(ipou_tun_fd, ipou_buf.hdr.data, size)) < 0)
		IPOU_PFATAL("write");

	IPOU_ASSERT((size_t)wrote == size);

	IPOU_PKTLOG("Sent ICMP destination unreachable to %s", dst);
}

void ipou_icmp_init(void)
{
	srand(time(NULL));
}

#if 0
static const struct { struct ipou_icmp_pkt4 hdrs; uint8_t data[56]; } pkt4 = {
	.hdrs = {
		.ip = {
			.version	= 4,
			.ihl		= 5,
			.dscp		= 0,
			.ecn		= 0,
			.total_len	= IPOU_HTONS(84),
			.id		= IPOU_HTONS(0xced7),
			.flags		= IPOU_HTONS(0x4000),
			.ttl		= 64,
			.protocol	= 1,
			.iphdr_cksum	= 0,
			.source_addr	= { .s_addr = IPOU_HTONL(0xac1ffa01) },
			.dest_addr	= { .s_addr = IPOU_HTONL(0xac1ffdeb) }
		},
		.icmp = {
			.type			= 8,
			.code			= 0,
			.cksum			= 0,
			.misc			= { .u32 = IPOU_HTONL(0x00040001) }
		}
	},
	.data = {
		0x74, 0x14, 0xdf, 0x62, 0x00, 0x00, 0x00, 0x00,
		0x3e, 0x3c, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
	}
};

static const struct { struct ipou_icmp_pkt6 hdrs; uint8_t data[56]; } pkt6 = {
	.hdrs = {
		.ip = {
			.version	= 6,
			.tc_hi		= 0,
			.tc_lo		= 0,
			.fl_hi		= 0x0d,
			.fl_lo		= IPOU_HTONS(0x5170),
			.data_len	= IPOU_HTONS(64),
			.next_hdr	= 58,
			.hop_limit	= 64,
			.source_addr	= { .s6_addr = {
						0xfd, 0x00, 0xd0, 0x0f,
						0x01, 0xab, 0x00, 0x01,
						0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x01
					} },
			.dest_addr	= { .s6_addr = {
						0xfd, 0x00, 0xd0, 0x0f,
						0x01, 0xab, 0x00, 0x02,
						0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x01
					} }
		},
		.icmp = {
			.type		= 128,
			.code		= 0,
			.cksum		= 0,
			.misc		= { .u32 = IPOU_HTONL(0x00040003) }
		}
	},
	.data = {
		0x00, 0xb6, 0xe6, 0x62, 0x00, 0x00, 0x00, 0x00,
		0xcd, 0x71, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
	}
};

#include <stdio.h>

int main(void)
{
	uint16_t sum;

	sum = ipou_icmp6_phdr_cksum1(&pkt6.hdrs.ip);
	sum = ipou_cksum_add(&pkt6.hdrs.icmp, 64, sum);
	printf("%hx\n", ntohs(sum));
	return 0;
}
#endif
