#include "ipoud.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

/*
 * <linux/ipv6.h> contains the definition of struct in6_ifreq, but it doesn't
 * have UAPI support on CentOS 7, so it conflicts with <netinet/ip.h>, which is
 * included via ipoud.h and iputil.h.  (This is true even though the kernel
 * headers identify themselves as version 3.10.0, which has UAPI support in the
 * kernel sources.)
 *
 * For now, assume that this problem is fixed by version 4.0.
 */
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
#define in6_pktinfo	IPOU_IN6_PKTINFO_NOREDEF
#define ip6_mtuinfo	IPOU_IP6_MTUINFO_NOREDEF
#endif
#include <linux/ipv6.h>

#define IPOU_TUN_FLAGS	(				\
				IFF_UP |		\
				IFF_POINTOPOINT |	\
				IFF_RUNNING |		\
				IFF_NOARP		\
	)

int ipou_tun_fd;
int ipou_tun_index;

static void ipou_set_tun_ip4(struct ifreq *const ifr)
{
	union ipou_sockaddr addr;
	int fd;  /* Need an AF_INET socket */

	if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		IPOU_FATAL("Failed to create IPv4 socket: %m");

	memset(&addr, 0, sizeof addr);
	addr.sin.sin_family = AF_INET;
	addr.sin.sin_addr = ipou_tun_addr4;
	memcpy(&ifr->ifr_addr, &addr.sa, sizeof addr.sa);

	if (ioctl(fd, SIOCSIFADDR, ifr) < 0)
		IPOU_FATAL("ioctl failed: SIOCSIFADDR: %m");

	addr.sin.sin_addr.s_addr = htonl(~((1U << (32 - ipou_tun_pfx4)) - 1));
	memcpy(&ifr->ifr_addr, &addr.sa, sizeof addr.sa);

	if (ioctl(fd, SIOCSIFNETMASK, ifr) < 0)
		IPOU_FATAL("ioctl failed: SIOCSIFNETMASK: %m");

	if (close(fd) < 0)
		IPOU_FATAL("Failed to close IPv4 socket: %m");
}

static void ipou_set_tun_ip6(void)
{
	/*
	 * Valgrind doesn't know about struct in6_ifreq, so it complains about
	 * uninitialized memory in the ioctl() call if we don't pass an
	 * initialized block at least as large as a struct ifreq.
	 *
	 * See https://bugs.kde.org/show_bug.cgi?id=457094
	 */
	union { struct in6_ifreq ifr6; struct ifreq ifr; } req;

	memset(&req, 0, sizeof req);
	req.ifr6.ifr6_addr = ipou_tun_addr6;
	req.ifr6.ifr6_prefixlen = ipou_tun_pfx6;
	req.ifr6.ifr6_ifindex = ipou_tun_index;

	if (ioctl(ipou_socket_fd, SIOCSIFADDR, &req.ifr6) < 0)
		IPOU_FATAL("ioctl failed: SIOCSIFADDR: %m");
}

void ipou_log_tun_cfg(void)
{
	char buf[INET6_ADDRSTRLEN];

	IPOU_DEBUG("Configured TUN interface: %s", ipou_tun_name);

	if (ipou_tun_addr4.s_addr != INADDR_ANY) {
		inet_ntop(AF_INET, &ipou_tun_addr4, buf, sizeof buf);
		IPOU_DEBUG("    IPv4 address: %s/%hhu", buf, ipou_tun_pfx4);
	}

	if (!IN6_IS_ADDR_UNSPECIFIED(&ipou_tun_addr6)) {
		inet_ntop(AF_INET6, &ipou_tun_addr6, buf, sizeof buf);
		IPOU_DEBUG("    IPv6 address: %s/%hhu", buf, ipou_tun_pfx6);
	}

	IPOU_DEBUG("    MTU: %" PRIu16, ipou_tun_mtu());
}

void ipou_tun_setup(void)
{
	struct ifreq ifr;

	if ((ipou_tun_fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK)) < 0)
		IPOU_FATAL("Failed to open /dev/net/tun: %m");

	memset(&ifr, 0, sizeof ifr);
	memcpy(ifr.ifr_name, ipou_tun_name, IFNAMSIZ);
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	if (ioctl(ipou_tun_fd, TUNSETIFF, &ifr) < 0)
		IPOU_FATAL("ioctl failed: TUNSETIFF: %m");

	if (ioctl(ipou_socket_fd, SIOCGIFINDEX, &ifr) < 0)
		IPOU_FATAL("ioctl failed: SIOCGIFINDEX: %m");

	ipou_tun_index = ifr.ifr_ifindex;
	memcpy(ipou_tun_name, ifr.ifr_name, IFNAMSIZ);
	ifr.ifr_mtu = ipou_tun_mtu();

	if (ioctl(ipou_socket_fd, SIOCSIFMTU, &ifr) < 0)
		IPOU_FATAL("ioctl failed: SIOCSIFMTU: %m");

	ipou_set_addrgenmode();

	if (ipou_tun_addr4.s_addr != INADDR_ANY)
		ipou_set_tun_ip4(&ifr);

	if (!IN6_IS_ADDR_UNSPECIFIED(&ipou_tun_addr6))
		ipou_set_tun_ip6();

	ifr.ifr_flags = IPOU_TUN_FLAGS;

	if (ioctl(ipou_socket_fd, SIOCSIFFLAGS, &ifr) < 0)
		IPOU_FATAL("ioctl failed: SIOCSIFFLAGS: %m");

	if (ipou_debug)
		ipou_log_tun_cfg();
}
