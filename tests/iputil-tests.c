#include "iputil.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARG_ASSERT(expr)						\
	do {								\
		if (!(expr)) {						\
			fprintf(stderr,					\
				"ASSERTION FAILED at line %d: %s\n",	\
				__LINE__, #expr);			\
			return NULL;						\
		}							\
	}								\
	while (0)

struct function_test {
	const char		*output;
	const char		*argv[3];
};

#define FTEST(_res, ...)			\
	{					\
		.output	= _res,		\
		.argv	= { __VA_ARGS__ }	\
	}

enum test_result {
	TEST_OK,
	TEST_FAIL,
	TEST_ERR
};

static int test_atoi(const char *const nptr)
{
	long value;
	char *endptr;

	if (*nptr == 0)
		return INT_MIN;

	errno = 0;
	value = strtol(nptr, &endptr, 10);

	if (errno != 0 || *endptr != 0 || value <= INT_MIN || value > INT_MAX)
		return INT_MIN;

	return value;
}

static const char *test_ipou_is_mcast4(const char *const *const argv)
{
	struct in_addr addr;

	ARG_ASSERT(inet_aton(argv[0], &addr) == 1);
	return ipou_is_mcast4(addr) ? "true" : "false";
}

static const struct function_test ipou_is_mcast4_tests[] = {
	FTEST("true", "224.0.0.0" ),
	{ 0 }
};

static const char *test_ipou_is_bcast4(const char *const *const argv)
{
	struct in_addr addr;

	ARG_ASSERT(inet_aton(argv[0], &addr) == 1);
	return ipou_is_bcast4(addr) ? "true" : "false";
}

static const struct function_test ipou_is_bcast4_tests[] = {
	FTEST("false", "224.0.0.0" ),
	{ 0 }
};

static const char *test_ipou_is_linklocal4(const char *const *const argv)
{
	struct in_addr addr;

	ARG_ASSERT(inet_aton(argv[0], &addr) == 1);
	return ipou_is_linklocal4(addr) ? "true" : "false";
}

static const struct function_test ipou_is_linklocal4_tests[] = {
	{ 0 }
};

static const char *test_ipou_is_loopback4(const char *const *const argv)
{
	struct in_addr addr;

	ARG_ASSERT(inet_aton(argv[0], &addr) == 1);
	return ipou_is_loopback4(addr) ? "true" : "false";
}

static const struct function_test ipou_is_loopback4_tests[] = {
	{ 0 }
};

static const char *test_ipou_mknetmask4(const char *const *const argv)
{
	int pfx_len;

	pfx_len = test_atoi(argv[0]);
	ARG_ASSERT(pfx_len >= 0 && pfx_len <= 32);
	return inet_ntoa(ipou_mknetmask4(pfx_len));
}

static const struct function_test ipou_mknetmask4_tests[] = {
	{ 0 }
};

static const char *test_ipou_is_netaddr4(const char *const *const argv)
{
	struct in_addr addr, netmask;
	int pfx_len;

	ARG_ASSERT(inet_aton(argv[0], &addr) == 1);
	pfx_len = test_atoi(argv[1]);
	ARG_ASSERT(pfx_len >= 0 && pfx_len <= 32);
	netmask = ipou_mknetmask4(pfx_len);
	return ipou_is_netaddr4(addr, netmask) ? "true" : "false";
}

static const struct function_test ipou_is_netaddr4_tests[] = {
	FTEST("false", "192.168.1.1", "24"),
	FTEST("true", "192.168.1.0", "24"),
	FTEST("true", "0.0.0.0", "0"),
	FTEST("false", "192.0.0.0", "0"),
	FTEST("false", "0.0.0.1", "0"),
	FTEST("true", "192.168.1.1", "32"),
	FTEST("true", "0.0.0.0", "32"),
	FTEST("true", "255.255.255.255", "32"),
	FTEST("true", "172.19.240.0", "20"),
	FTEST("false", "172.19.8.0", "20"),
	{ 0 }
};

static const char *test_ipou_in_net4(const char *const *const argv)
{
	struct in_addr hostaddr, netaddr, netmask;
	int pfx_len;

	ARG_ASSERT(inet_aton(argv[0], &hostaddr) == 1);
	ARG_ASSERT(inet_aton(argv[1], &netaddr) == 1);
	pfx_len = test_atoi(argv[2]);
	ARG_ASSERT(pfx_len >= 0 && pfx_len <= 32);
	netmask = ipou_mknetmask4(pfx_len);
	ARG_ASSERT(ipou_is_netaddr4(netaddr, netmask));
	return ipou_in_net4(hostaddr, netaddr, netmask) ? "true" : "false";
}

static const struct function_test ipou_in_net4_tests[] = {
	FTEST("true", "192.168.1.1", "192.168.1.0", "24"),
	FTEST("true", "192.168.1.1", "0.0.0.0", "0"),
	{ 0 }
};

static const char *test_ipou_is_netcast4(const char *const *const argv)
{
	struct in_addr addr, netmask;
	int pfx_len;

	ARG_ASSERT(inet_aton(argv[0], &addr) == 1);
	pfx_len = test_atoi(argv[1]);
	ARG_ASSERT(pfx_len >= 0 && pfx_len <= 32);
	netmask = ipou_mknetmask4(pfx_len);
	return ipou_is_netcast4(addr, netmask) ? "true" : "false";
}

static const struct function_test ipou_is_netcast4_tests[] = {
	FTEST("false", "192.168.1.254", "24"),
	FTEST("true", "192.168.1.255", "24"),
	FTEST("true", "255.255.255.255", "0"),
	FTEST("false", "192.0.0.0", "0"),
	FTEST("false", "0.0.0.1", "0"),
	FTEST("true", "192.168.1.1", "32"),
	FTEST("true", "0.0.0.0", "32"),
	FTEST("true", "255.255.255.255", "32"),
	FTEST("true", "172.19.15.255", "20"),
	FTEST("false", "172.19.247.255", "20"),
	{ 0 }
};

static const char *test_ipou_mknetaddr4(const char *const *const argv)
{
	struct in_addr hostaddr, netmask;
	int pfx_len;

	ARG_ASSERT(inet_aton(argv[0], &hostaddr) == 1);
	pfx_len = test_atoi(argv[1]);
	ARG_ASSERT(pfx_len >= 0 && pfx_len <= 32);
	netmask = ipou_mknetmask4(pfx_len);
	return inet_ntoa(ipou_mknetaddr4(hostaddr, netmask));
}

static const struct function_test ipou_mknetaddr4_tests[] = {
	{ 0 }
};

static const char *test_ipou_addr_add4(const char *const *const argv)
{
	struct in_addr addr;
	int addend;

	ARG_ASSERT(inet_aton(argv[0], &addr) == 1);
	addend = test_atoi(argv[1]);
	ARG_ASSERT(addend >= 0 && addend <= 255);
	return inet_ntoa(ipou_addr_add4(addr, addend));
}

static const struct function_test ipou_addr_add4_tests[] = {
	{ 0 }
};

static const char *test_ipou_addr_sub4(const char *const *const argv)
{
	struct in_addr addr;
	int subtrahend;

	ARG_ASSERT(inet_aton(argv[0], &addr) == 1);
	subtrahend = test_atoi(argv[1]);
	ARG_ASSERT(subtrahend >= 0 && subtrahend <= 255);
	return inet_ntoa(ipou_addr_sub4(addr, subtrahend));
}

static const struct function_test ipou_addr_sub4_tests[] = {
	{ 0 }
};

static const char *test_ipou_in_range4(const char *const *const argv)
{
	struct in_addr addr, base, max;

	ARG_ASSERT(inet_aton(argv[0], &addr) == 1);
	ARG_ASSERT(inet_aton(argv[1], &base) == 1);
	ARG_ASSERT(inet_aton(argv[2], &max) == 1);
	ARG_ASSERT(ntohl(base.s_addr) <= ntohl(max.s_addr));
	return ipou_in_range4(addr, base, max) ? "true" : "false";
}

static const struct function_test ipou_in_range4_tests[] = {
	FTEST("true", "172.19.0.5", "172.19.0.1", "172.19.0.10"),
	FTEST("true", "172.19.0.1", "172.19.0.1", "172.19.0.10"),
	FTEST("true", "172.19.0.10", "172.19.0.1", "172.19.0.10"),
	FTEST("false", "172.19.0.0", "172.19.0.1", "172.19.0.10"),
	FTEST("false", "172.19.0.11", "172.19.0.1", "172.19.0.10"),
	FTEST("true", "0.0.0.0", "0.0.0.0", "255.255.255.255"),
	FTEST("true", "255.255.255.255", "0.0.0.0", "255.255.255.255"),
	FTEST("true", "127.0.0.1", "0.0.0.0", "255.255.255.255"),
	FTEST("true", "127.0.0.1", "127.0.0.1", "127.0.0.1"),
	FTEST("false", "127.0.0.0", "127.0.0.1", "127.0.0.1"),
	FTEST("false", "127.0.0.2", "127.0.0.1", "127.0.0.1"),
	{ 0 }
};




static const char *test_ipou_mknetmask6(const char *const *const argv)
{
	static char buf[INET6_ADDRSTRLEN];
	struct in6_addr netmask;
	int pfx_len;

	pfx_len = test_atoi(argv[0]);
	ARG_ASSERT(pfx_len >= 0 && pfx_len <= 128);
	ipou_mknetmask6(pfx_len, &netmask);
	assert(inet_ntop(AF_INET6, &netmask, buf, sizeof buf) == buf);
	return buf;
}

static const struct function_test ipou_mknetmask6_tests[] = {
	FTEST("ffff:ffff:ffff:ffff::", "64"),
	FTEST("ffff:ffff:ffff:fffe::", "63"),
	FTEST("ffff:ffff:ffff:ffff:8000::", "65"),
	FTEST("ffff:ffff:ffff:ff80::", "57"),
	FTEST("ffff:ffff:ffff:ff00::", "56"),
	FTEST("ffff:ffff:ffff:f000::", "52"),
	FTEST("::", "0"),
	FTEST("8000::", "1"),
	FTEST("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "128"),
	FTEST("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", "127"),
	{ 0 }
};

static const char *test_ipou_is_netaddr6(const char *const *const argv)
{
	struct in6_addr addr, netmask;
	int pfx_len;

	ARG_ASSERT(inet_pton(AF_INET6, argv[0], &addr) == 1);
	pfx_len = test_atoi(argv[1]);
	ARG_ASSERT(pfx_len >= 0 && pfx_len <= 128);
	ipou_mknetmask6(pfx_len, &netmask);
	return ipou_is_netaddr6(&addr, &netmask) ? "true" : "false";
}

static const struct function_test ipou_is_netaddr6_tests[] = {
	FTEST("true", "fd00:dead:beef:cafe::", "64"),
	FTEST("false", "fd00:dead:beef:cafe::1", "64"),
	FTEST("false", "fd00:dead:beef:cafe:8000::", "64"),
	FTEST("true", "fd00:dead:beef:cafe:8000::", "65"),
	FTEST("true", "::", "0"),
	FTEST("false", "8000::", "0"),
	FTEST("true", "fd00:dead:beef:cafe:efac:feeb:daed:00df", "128"),
	FTEST("true", "fd00:beef:cafe:ff00::", "56"),
	FTEST("false", "fd00:beef:cafe:ff80::", "56"),
	{ 0 }
};

static const char *test_ipou_in_net6(const char *const *const argv)
{
	struct in6_addr hostaddr, netaddr,  netmask;
	int pfx_len;

	ARG_ASSERT(inet_pton(AF_INET6, argv[0], &hostaddr) == 1);
	ARG_ASSERT(inet_pton(AF_INET6, argv[1], &netaddr) == 1);
	pfx_len = atoi(argv[2]);
	ARG_ASSERT(pfx_len >= 0 && pfx_len <= 128);
	ipou_mknetmask6(pfx_len, &netmask);
	ARG_ASSERT(ipou_is_netaddr6(&netaddr, &netmask));
	return ipou_in_net6(&hostaddr, &netaddr, &netmask) ? "true" : "false";
}

static const struct function_test ipou_in_net6_tests[] = {
	FTEST("true", "fd00:dead:beef:cafe::1", "fd00:dead:beef:cafe::", "64"),
	FTEST("false", "fd00:dead:feeb:cafe::1", "fd00:dead:beef:cafe::", "64"),
	FTEST("true", "fd00:dead:beef:cafe::1", "::", "0"),
	FTEST("true", "fd00:dead:beef:cafe::1",
	      "fd00:dead:beef:cafe::1", "128"),
	FTEST("false", "fd00:dead:beef:cafe::1",
	      "fd00:dead:beef:cafe::", "128"),
	FTEST("true", "fd00:dead:beef:cafe::1", "fd00:dead:beef:ca00::", "56"),
	FTEST("true", "fd00:dead:beef:caff::", "fd00:dead:beef:ca00::", "56"),
	FTEST("false", "fd00:dead:beef::1", "fd00:dead:beef:ca00::", "56"),
	{ 0 }
};

static const char *test_ipou_addr_add6(const char *const *const argv)
{
	static char buf[INET6_ADDRSTRLEN];
	struct in6_addr addr;
	int addend;

	ARG_ASSERT(inet_pton(AF_INET6, argv[0], &addr) == 1);
	addend = test_atoi(argv[1]);
	ARG_ASSERT(addend >= 0 && addend <= 255);
	ipou_addr_add6(&addr, addend);
	assert(inet_ntop(AF_INET6, &addr, buf, sizeof buf) == buf);
	return buf;
}

static const struct function_test ipou_addr_add6_tests[] = {
	FTEST("fd00:dead:beef:cafe::c9", "fd00:dead:beef:cafe::1", "200"),
	FTEST("fd00:dead:beef:caff::",
	      "fd00:dead:beef:cafe:ffff:ffff:ffff:ffff", "1"),
	FTEST("::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "1"),
	FTEST("::1","ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "2"),
	FTEST("fd00:dead:beef:cafe::1", "fd00:dead:beef:cafe::1", "0"),
	{ 0 }
};

static const char *test_ipou_addr_sub6(const char *const *const argv)
{
	static char buf[INET6_ADDRSTRLEN];
	struct in6_addr addr;
	int subtrahend;

	ARG_ASSERT(inet_pton(AF_INET6, argv[0], &addr) == 1);
	subtrahend = test_atoi(argv[1]);
	ARG_ASSERT(subtrahend >= 0 && subtrahend <= 255);
	ipou_addr_sub6(&addr, subtrahend);
	assert(inet_ntop(AF_INET6, &addr, buf, sizeof buf) == buf);
	return buf;
}

static const struct function_test ipou_addr_sub6_tests[] = {
	FTEST("fd00:dead:beef:cafe::1", "fd00:dead:beef:cafe::c9", "200"),
	FTEST("fd00:dead:beef:cafe:ffff:ffff:ffff:ffff",
	      "fd00:dead:beef:caff::", "1"),
	FTEST("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::", "1"),
	FTEST("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::1", "2"),
	FTEST("fd00:dead:beef:cafe::1", "fd00:dead:beef:cafe::1", "0"),
	{ 0 }
};

static const char *test_ipou_mknetaddr6(const char *const *const argv)
{
	static char buf[INET6_ADDRSTRLEN];
	struct in6_addr hostaddr, netmask, netaddr;
	int pfx_len;

	ARG_ASSERT(inet_pton(AF_INET6, argv[0], &hostaddr) == 1);
	pfx_len = test_atoi(argv[1]);
	ARG_ASSERT(pfx_len >= 0 && pfx_len <= 128);
	ipou_mknetmask6(pfx_len, &netmask);
	ipou_mknetaddr6(&hostaddr, &netmask, &netaddr);
	assert(inet_ntop(AF_INET6, &netaddr, buf, sizeof buf) == buf);
	return buf;
}

static const struct function_test ipou_mknetaddr6_tests[] = {
	FTEST("fd00:dead:beef:cafe::", "fd00:dead:beef:cafe::1", "64"),
	FTEST("fd00:dead:beef:cafe::", "fd00:dead:beef:cafe:8000::", "64"),
	FTEST("fd00:dead:beef:ca00::", "fd00:dead:beef:cafe::", "56"),
	FTEST("::", "fd00:dead:beef:cafe:efac:feeb:daed:00df", "0"),
	FTEST("fd00:dead:beef:cafe:efac:feeb:daed:df",
	      "fd00:dead:beef:cafe:efac:feeb:daed:00df", "128"),
	{ 0 }
};

static const char *test_ipou_in_range6(const char *const *const argv)
{
	struct in6_addr addr, base, max;

	ARG_ASSERT(inet_pton(AF_INET6, argv[0], &addr) == 1);
	ARG_ASSERT(inet_pton(AF_INET6, argv[1], &base) == 1);
	ARG_ASSERT(inet_pton(AF_INET6, argv[2], &max) == 1);
	ARG_ASSERT(memcmp(&base, &max, sizeof max) <= 0);
	return ipou_in_range6(&addr, &base, &max) ? "true" : "false";
}

static const struct function_test ipou_in_range6_tests[] = {
	FTEST("true", "fd00::5", "fd00::1", "fd00::a"),
	FTEST("true", "fd00::1", "fd00::1", "fd00::a"),
	FTEST("true", "fd00::a", "fd00::1", "fd00::a"),
	FTEST("false", "fd00::", "fd00::1", "fd00::a"),
	FTEST("false", "fd00::b", "fd00::1", "fd00::a"),
	FTEST("true", "::", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
	FTEST("true", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	      "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
	FTEST("true", "fd00:dead:beef:cafe::5",
	      "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
	FTEST("true", "fd00::5", "fd00::5", "fd00::5"),
	FTEST("false", "fd00::4", "fd00::5", "fd00::5"),
	FTEST("false", "fd00::3", "fd00::5", "fd00::5"),
	{ 0 }
};

struct test_function {
	const char			*fn_name;
	const char			*(*test_fn)(const char *const *argv);
	const char			*args;
	const struct function_test	*tests;
	unsigned int			argc;
};

#define TEST_FN(_name, _argc, _args)			\
	{						\
		.fn_name	= #_name,		\
		.test_fn	= test_##_name,		\
		.args		= _args,		\
		.tests		= _name##_tests,	\
		.argc		= _argc			\
	}

static const struct test_function test_functions[] = {
	TEST_FN(ipou_is_mcast4, 1, "addr"),
	TEST_FN(ipou_is_bcast4, 1, "addr"),
	TEST_FN(ipou_is_linklocal4, 1, "addr"),
	TEST_FN(ipou_is_loopback4, 1, "addr"),
	TEST_FN(ipou_mknetmask4, 1, "pfx_len"),
	TEST_FN(ipou_is_netaddr4, 2, "addr pfx_len"),
	TEST_FN(ipou_in_net4, 3, "hostaddr netaddr pfx_len"),
	TEST_FN(ipou_is_netcast4, 2, "addr pfx_len"),
	TEST_FN(ipou_mknetaddr4, 2, "hostaddr pfx_len"),
	TEST_FN(ipou_addr_add4, 2, "addr addend"),
	TEST_FN(ipou_addr_sub4, 2, "addr subtrahend"),
	TEST_FN(ipou_in_range4, 3, "addr base max"),
	TEST_FN(ipou_mknetmask6, 1, "pfx_len"),
	TEST_FN(ipou_is_netaddr6, 2, "addr pfx_len"),
	TEST_FN(ipou_in_net6, 3, "hostaddr netaddr pfx_len"),
	TEST_FN(ipou_addr_add6, 2, "addr addend"),
	TEST_FN(ipou_addr_sub6, 2, "addr subtrahend"),
	TEST_FN(ipou_mknetaddr6, 2, "hostaddr pfx_len"),
	TEST_FN(ipou_in_range6, 3, "addr base max"),
	{ 0 }
};

static void print_argv(const char *const *const argv, unsigned int argc)
{
	unsigned int i;

	for (i = 0; i < argc; ++i)
		fprintf(stderr, "%s ", argv[i]);
}

static enum test_result run_test(const struct test_function *const tf,
				 const struct function_test *const ft)
{
	const char *result;

	if ((result = tf->test_fn(ft->argv)) == NULL) {
		fprintf(stderr, "ERROR: %s: ", tf->fn_name);
		print_argv(ft->argv, tf->argc);
		fputc('\n', stderr);
		return TEST_ERR;
	}

	if (strcmp(result, ft->output) != 0) {
		fprintf(stderr, "FAILED: %s: ", tf->fn_name);
		print_argv(ft->argv, tf->argc);
		fprintf(stderr, "(expected %s)\n", ft->output);
		return TEST_FAIL;
	}

	return TEST_OK;
}

static int auto_tests(void)
{
	unsigned int fn_ran, fn_ok, fn_fail, fn_err, ran, ok, fail, err;
	const struct test_function *tf;
	const struct function_test *ft;

	ran = ok = fail = err = 0;

	for (tf = test_functions; tf->fn_name != NULL; ++tf) {

		fn_ran = fn_ok = fn_fail = fn_err = 0;

		for (ft = tf->tests; ft->output != NULL; ++ft) {

			++fn_ran;

			switch (run_test(tf, ft)) {

				case TEST_OK:	++fn_ok;
						break;

				case TEST_FAIL:	++fn_fail;
						break;

				case TEST_ERR:	++fn_err;
						break;
			}
		}

		ran += fn_ran;
		ok += fn_ok;
		fail += fn_fail;
		err += fn_err;

		printf("\n%s:\n", tf->fn_name);
		printf("    tests: %d\n", fn_ran);
		printf("    succeeded: %d\n", fn_ok);
		printf("    failed: %d\n", fn_fail);
		printf("    errors: %d\n", fn_err);
	}

	puts("\nTOTAL:");
	printf("    tests: %d\n", ran);
	printf("    succeeded: %d\n", ok);
	printf("    failed: %d\n", fail);
	printf("    errors: %d\n\n", err);
	putchar('\n');

	return -(fail + err);
}



int main(const int argc, char **const argv)
{
	const char *const *const cargv = (const char *const *)argv;
	const struct test_function *tf;
	const char *result;

	if (argc < 2) {
		fprintf(stderr,
			"%s requires at least 1 argument (function to test)\n",
			argv[0]);
		exit(1);
	}

	if (strcmp(cargv[1], "auto") == 0)
		exit(auto_tests() != 0);

	for (tf = test_functions; tf->fn_name != NULL; ++tf) {

		if (strcmp(cargv[1], tf->fn_name) == 0) {

			if ((unsigned int)argc != 2 + tf->argc) {
				fprintf(stderr,
					"%s %s requires %u arguments (%s)\n",
					cargv[0], cargv[1], tf->argc, tf->args);
				exit(1);
			}

			if ((result = tf->test_fn(cargv + 2)) == NULL) {
				fputs("Invalid argument\n", stderr);
				exit(1);
			}

			puts(result);
			exit(0);
		}
	}

	fprintf(stderr, "Unrecognized function: %s\n", argv[1]);
	exit(1);
}
