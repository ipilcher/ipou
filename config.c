#include "ipoud.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <savl.h>
#include <unistd.h>

/* Where did a configuration setting come from? */
#define IPOU_WHERE_EARLY	(uint8_t)0
#define IPOU_WHERE_ARGV		(uint8_t)1
#define IPOU_WHERE_FILE		(uint8_t)2

/* Number of options in ipou_cfg_opts[] */
#define IPOU_CFG_OPTS_COUNT	20

struct ipou_cfg_item {
	const struct ipou_cfg_opt	*opt;
	char				*value;
	struct savl_node		node;
	unsigned char			where;
	unsigned short			line;
};

struct ipou_cfg_opt {
	const char	*name;
	const char	*desc;
	void		(*parse_fn)(const struct ipou_cfg_item *item);
	unsigned int	early:1;  /* early CLI option? */
	unsigned int	file:1;  /* allowed in config file? */
	unsigned int	value:1;  /* value allowed (and required)? */
	unsigned int	server:1;  /* allowed in server mode? */
	unsigned int	client:1;  /* allowed in client mode? */
	unsigned int	required:1;
};

char ipou_tun_name[IFNAMSIZ] = "ipou%d";
_Bool ipou_debug = 0;
_Bool ipou_log_pkts = 0;
enum ipou_op_mode ipou_mode = IPOU_MODE_UNSET;
uint8_t ipou_max_clients = 16;
uint8_t ipou_hello_routes = 0;
uint16_t ipou_max_msg_size;
int ipou_peer_timeout = 360;  /* 6 minutes; ping after 3 minutes */

union ipou_sockaddr ipou_server = {
	.sin6 = {
		.sin6_family	= AF_INET6,
		.sin6_port	= IPOU_HTONS(IPOU_DEF_UDP_PORT),
		.sin6_addr	= IN6ADDR_ANY_INIT
	}
};

struct in_addr ipou_tun_addr4 = { .s_addr = INADDR_ANY };
uint8_t ipou_tun_pfx4 = 0;
struct in_addr ipou_tun_netmask4;
struct in_addr ipou_tun_netaddr4;
struct in_addr ipou_pool4 = { .s_addr = INADDR_ANY };
struct ipou_cfg_route4 *ipou_cfg_routes4 = NULL;

struct in6_addr ipou_tun_addr6 = IN6ADDR_ANY_INIT;
uint8_t ipou_tun_pfx6 = 64;
struct in6_addr ipou_tun_netmask6;
struct in6_addr ipou_tun_netaddr6;
struct in6_addr ipou_pool6 = IN6ADDR_ANY_INIT;
struct ipou_cfg_route6 *ipou_cfg_routes6 = NULL;

static const char *ipou_cfg_file = IPOU_DEF_CFG_FILE;
static struct savl_node *ipou_cfg = NULL;
static const struct ipou_cfg_opt ipou_cfg_opts[];
static uint16_t ipou_path_mtu = 1500;


/*
 *
 *	Configuration AVL tree
 *
 */

static
struct ipou_cfg_item *ipou_node_to_item(const struct savl_node *const node)
{
	return (node == NULL) ? NULL :
			SAVL_NODE_CONTAINER(node, struct ipou_cfg_item, node);
}

static
int ipou_cmp_items(const union savl_key key, const struct savl_node *const node)
{
	return strcmp(key.p, ipou_node_to_item(node)->opt->name);
}

static struct ipou_cfg_item *ipou_get_item(const char *const name)
{
	const struct savl_node *node;

	node = savl_get(ipou_cfg, ipou_cmp_items,
			(union savl_key){ .p = name });

	return ipou_node_to_item(node);
}

static void ipou_free_item(struct savl_node *const node)
{
	struct ipou_cfg_item *item;

	item = ipou_node_to_item(node);
	free(item->value);
	free(item);
}


/*
 *
 *	Post-parsing config validation
 *
 */

static char *ipou_fmt_item1(const char *restrict const name,
			    const char *restrict const value,
			    const unsigned char where,
			    const unsigned short line)
{
	if (where == IPOU_WHERE_FILE) {
		return IPOU_ASPRINTF("'%s%s%s' at %s:%hu", name,
				     value == NULL ? "" : "=",
				     value == NULL ? "" : value,
				     ipou_cfg_file, line);
	}
	else {
		return IPOU_ASPRINTF("'%s%s%s' on command line", name,
				     value == NULL ? "" : "=",
				     value == NULL ? "" : value);
	}
}

static char *ipou_fmt_item2(const struct ipou_cfg_item *const item)
{
	return ipou_fmt_item1(item->opt->name, item->value,
			      item->where, item->line);
}

static void ipou_validate_server_ipv4(void)
{
	struct in_addr pool_max;

	if (ipou_pool4.s_addr == INADDR_ANY)
		IPOU_FATAL("'ipv4-tun-address' requires 'ipv4-pool-base'");

	if (!ipou_in_net4(ipou_pool4, ipou_tun_netaddr4, ipou_tun_netmask4))
		IPOU_FATAL("IPv4 pool base is outside tunnel subnet");
	if (ipou_is_netaddr4(ipou_pool4, ipou_tun_netmask4))
		IPOU_WARNING("IPv4 pool base is a network address");
	if (ipou_is_netcast4(ipou_pool4, ipou_tun_netmask4))
		IPOU_WARNING("IPv4 pool base is a broadcast address");

	pool_max = ipou_addr_add4(ipou_pool4, ipou_max_clients - 1);

	if (!ipou_in_net4(pool_max, ipou_tun_netaddr4, ipou_tun_netmask4))
		IPOU_FATAL("IPv4 pool end is outside tunnel subnet");
	if (ipou_is_netaddr4(pool_max, ipou_tun_netmask4))
		IPOU_WARNING("IPv4 pool end is a network address");
	if (ipou_is_netcast4(pool_max, ipou_tun_netmask4))
		IPOU_WARNING("IPv4 pool end is a broadcast address");

	if (ipou_in_range4(ipou_tun_addr4, ipou_pool4, pool_max))
		IPOU_FATAL("Tunnel interface IPv4 address is within IPv4 pool");

}

static void ipou_validate_server_ipv6(void)
{
	struct in6_addr pool_max;

	if (IN6_IS_ADDR_UNSPECIFIED(&ipou_pool6))
		IPOU_FATAL("'ipv6-tun-address' requires 'ipv6-pool-base'");

	if (!ipou_in_net6(&ipou_pool6, &ipou_tun_netaddr6, &ipou_tun_netmask6))
		IPOU_FATAL("IPv6 pool base is outside tunnel subnet");
	if (ipou_is_netaddr6(&ipou_pool6, &ipou_tun_netmask6))
		IPOU_WARNING("IPv6 pool base is a network address");

	pool_max = ipou_pool6;
	ipou_addr_add6(&pool_max, ipou_max_clients - 1);

	if (!ipou_in_net6(&pool_max, &ipou_tun_netaddr6, &ipou_tun_netmask6))
		IPOU_FATAL("IPv6 pool end is outside tunnel subnet");
	if (ipou_is_netaddr6(&pool_max, &ipou_tun_netmask6))
		IPOU_WARNING("IPv6 pool end is a network address");

	/*
	 * Ensure that address pool doesn't span different /96 address ranges,
	 * so ipou_server_pkt_client6() in server.c can identify destination
	 * client with 32-bit subtraction.  (Subnet size is already limited to
	 * /64 by ipou_parse_tun_addr6().)
	 */
	if (ipou_pool6.__in6_u.__u6_addr32[2]
				!= pool_max.__in6_u.__u6_addr32[2])
		IPOU_FATAL("IPv6 pool spans different /96 address ranges");

	if (ipou_in_range6(&ipou_tun_addr6, &ipou_pool6, &pool_max))
		IPOU_FATAL("Tunnel interface IPv6 address is within IPv6 pool");
}

static void ipou_validate_server_cfg(void)
{
	size_t welcome_size;

	if (IN6_IS_ADDR_UNSPECIFIED(&ipou_tun_addr6)) {

		if (ipou_tun_addr4.s_addr == INADDR_ANY) {
			IPOU_FATAL("Server mode requires at least one of "
				   "'ipv4-tun-address' or 'ipv6-tun-address' "
				   "to be set");
		}

		if (ipou_cfg_routes6 != NULL)
			IPOU_FATAL("'ipv6-routes' requires 'ipv6-tun-address'");
	}
	else {
		ipou_validate_server_ipv6();
	}


	if (ipou_tun_addr4.s_addr == INADDR_ANY) {

		if (ipou_cfg_routes4 != NULL)
			IPOU_FATAL("'ipv4-routes' requires 'ipv4-tun-address'");
	}
	else {
		ipou_validate_server_ipv4();
	}

	/* Calculate max msg size, based on path MTU & listen address IP ver */
	if (IN6_IS_ADDR_V4MAPPED(&ipou_server.sin6.sin6_addr))
		ipou_max_msg_size = ipou_path_mtu - IPOU_IPUDP_HDR_SIZE4;
	else
		ipou_max_msg_size = ipou_path_mtu - IPOU_IPUDP_HDR_SIZE6;

	/* Calculate number of ipou_msg_route unions needed in HELLO message */
	ipou_hello_routes =
		(ipou_cfg_routes4 == NULL) ? 0 : ipou_cfg_routes4->count;
	ipou_hello_routes = (ipou_hello_routes + 1) / 2;
	ipou_hello_routes +=
		(ipou_cfg_routes6 == NULL) ? 0 : ipou_cfg_routes6->count;

	welcome_size = sizeof ipou_buf.welcome
			+ sizeof(union ipou_msg_route) * ipou_hello_routes;

	if (welcome_size > ipou_max_msg_size)
		IPOU_FATAL("Too many routes for WELCOME message");
}

static void ipou_validate_cfg(void)
{
	struct ipou_cfg_item *item;
	const struct ipou_cfg_opt *opt;
	unsigned int i;

	if (ipou_mode == IPOU_MODE_UNSET)
		IPOU_FATAL("Operating mode ('client' or 'server') not set");

	item = ipou_node_to_item(savl_first(ipou_cfg));

	while ((item = ipou_node_to_item(savl_next(&item->node))) != NULL) {

		if (ipou_mode == IPOU_MODE_SERVER && item->opt->server)
			continue;
		if (ipou_mode == IPOU_MODE_CLIENT && item->opt->client)
			continue;

		IPOU_FATAL("Option %s not allowed in %s mode: %s",
			   ipou_mode == IPOU_MODE_SERVER ? "server" : "client",
			   item->opt->name, ipou_fmt_item2(item));
	}

	for (i = 0; i < IPOU_CFG_OPTS_COUNT; ++i) {

		opt = &ipou_cfg_opts[i];

		if (ipou_mode == IPOU_MODE_SERVER && !opt->server)
			continue;
		if (ipou_mode  == IPOU_MODE_CLIENT && !opt->client)
			continue;
		if (!opt->required)
			continue;

		if (ipou_get_item(opt->name) == NULL)
			IPOU_FATAL("Required option %s not set", opt->name);
	}

	if (ipou_mode == IPOU_MODE_SERVER)
		ipou_validate_server_cfg();
}


/*
 *
 *	Parse config options
 *
 */

static void ipou_dupe_item(const struct ipou_cfg_item *const restrict item,
			   const struct ipou_cfg_item *const restrict existing)
{
	char *item_str, *existing_str;

	item_str = ipou_fmt_item2(item);
	existing_str = ipou_fmt_item2(existing);

	/* New item must be at least as recent as existing item. */
	IPOU_ASSERT(item->where >= existing->where);

	/* Both items from same place (config file or commnd line) is error */
	if ((item->where == IPOU_WHERE_FILE)
				== (existing->where == IPOU_WHERE_FILE)) {
		IPOU_FATAL("Duplicate config options: %s and %s",
			   existing_str, item_str);
	}

	/* If from different places, command line overrides config file */
	IPOU_INFO("Ignoring config option %s; overridden by %s",
		  item_str, existing_str);

	free(item_str);
	free(existing_str);
}

static int ipou_name_cmp(const void *const key, const void *const memb)
{
	const struct ipou_cfg_opt *opt;
	const char *item;
	ptrdiff_t len;
	int result;

	item = key;
	opt = memb;

	len = strchrnul(item, '=') - item;
	IPOU_ASSERT(len >= 0);

	if ((result = strncmp(item, opt->name, len)) != 0)
		return result;

	return len - strlen(opt->name);
}

static const char *ipou_item_value(const char *const item,
				   const struct ipou_cfg_opt *const opt,
				   const unsigned char where,
				   const unsigned short line)
{
	const char *value;

	value = item + strlen(opt->name);
	IPOU_ASSERT(*value == '=' || *value == 0);

	if (*value == '=')
		++value;
	else
		value = NULL;

	if ((value == NULL) == opt->value) {
		IPOU_FATAL("Value %s for option: %s",
			   opt->value ? "required" : "not allowed",
			   ipou_fmt_item1(opt->name, value, where, line));
	}

	return value;
}

static void ipou_do_opt(const char *restrict const item_str,
			 const struct ipou_cfg_opt *const opt,
			 const unsigned char where, const unsigned short line)
{
	struct ipou_cfg_item *item;
	struct savl_node *node;
	const char *value;

	if (where == IPOU_WHERE_EARLY && !opt->early)
		return;

	if (where == IPOU_WHERE_ARGV && opt->early)
		return;

	value = ipou_item_value(item_str, opt, where, line);

	if (where == IPOU_WHERE_FILE && !opt->file) {

		IPOU_FATAL("Option not allowed in config file: %s",
			   ipou_fmt_item1(opt->name, value, where, line));
	}

	item = IPOU_ZALLOC(sizeof *item);
	item->opt = opt;
	item->value = (value == NULL) ? NULL : IPOU_STRDUP(value);
	item->where = where;
	item->line = line;

	node = savl_try_add(&ipou_cfg, ipou_cmp_items,
			    (union savl_key){ .p = opt->name }, &item->node);

	if (node != NULL)
		ipou_dupe_item(item, ipou_node_to_item(node));
}

static void ipou_check_opts(const char *restrict const item,
			    const unsigned char where,
			    const unsigned short line)
{
	const struct ipou_cfg_opt *opt;

	opt = bsearch(item, ipou_cfg_opts, IPOU_CFG_OPTS_COUNT,
		      sizeof *opt, ipou_name_cmp);

	if (opt == NULL) {

		if (where == IPOU_WHERE_EARLY)
			return;

		IPOU_FATAL("Invalid config option: %s",
			   ipou_fmt_item1(item, NULL, where, line));
	}

	ipou_do_opt(item, opt, where, line);
}

static void ipou_log_opt(const struct ipou_cfg_item *const item)
{
	char *where;

	if (!ipou_debug)
		return;

	where = ipou_fmt_item2(item);
	IPOU_DEBUG("Set %s: %s", item->opt->desc, where);
	free(where);
}

static void ipou_early_argv(char **const argv)
{
	/*
	 * Debugging will never be enabled first time log-to is processed,
	 * so process it a second time to log debug message after debugging
	 * is (potentially) enabled.
	 */
	static const char *const early_opts[] = {
		"help", "log-to", "debug", "log-to", NULL
	};

	struct ipou_cfg_item *item;
	const char *const *opt_name;
	char **arg;

	ipou_use_syslog = !isatty(STDERR_FILENO);
	setlinebuf(stderr);

	for (arg = argv + 1; *arg != NULL; ++arg)
		ipou_check_opts(*arg, IPOU_WHERE_EARLY, 0);

	for (opt_name = early_opts; *opt_name != NULL; ++opt_name) {

		if ((item = ipou_get_item(*opt_name)) != NULL) {
			IPOU_ASSERT(item->opt->early);
			item->opt->parse_fn(item);
			ipou_log_opt(item);
		}
	}
}

static void ipou_argv(char **const argv)
{
	struct ipou_cfg_item *item;
	char **arg;

	for (arg = argv + 1; *arg != NULL; ++arg)
		ipou_check_opts(*arg, IPOU_WHERE_ARGV, 0);

	item = ipou_node_to_item(savl_first(ipou_cfg));

	while (item != NULL) {

		if (item->where == IPOU_WHERE_ARGV) {
			item->opt->parse_fn(item);
			ipou_log_opt(item);
		}

		item = ipou_node_to_item(savl_next(&item->node));
	}
}

static void ipou_file(void)
{
	struct ipou_cfg_item *item;
	unsigned short line_no;
	char *line, *first;
	size_t size;
	FILE *file;

	if (strcmp(ipou_cfg_file, "none") == 0)
		return;

	if ((file = fopen(ipou_cfg_file, "r")) == NULL)
		IPOU_FATAL("Failed to open %s: %m", ipou_cfg_file);

	line = NULL;
	line_no = 0;

	while (++line_no, getline(&line, &size, file) >= 0) {

		if (line_no == 0)  /* detect rollover */
			IPOU_FATAL("Config file too long: %s", ipou_cfg_file);

		for (first = line; isspace(*first); ++first);

		if (*first == '#' || *first == '\n' || *first == 0)
			continue;

		*strchrnul(first, '\n') = 0;

		ipou_check_opts(first, IPOU_WHERE_FILE, line_no);
	}

	if (!feof(file))
		IPOU_FATAL("Failed to read %s: %m", ipou_cfg_file);

	if (fclose(file) != 0)
		IPOU_FATAL("Failed to close %s: %m", ipou_cfg_file);

	free(line);

	item = ipou_node_to_item(savl_first(ipou_cfg));

	while (item != NULL) {

		if (item->where == IPOU_WHERE_FILE) {
			item->opt->parse_fn(item);
			ipou_log_opt(item);
		}

		item = ipou_node_to_item(savl_next(&item->node));
	}
}

void ipou_get_config(char **const argv)
{
	ipou_early_argv(argv);
	ipou_argv(argv);
	ipou_file();
	ipou_validate_cfg();
	savl_free(&ipou_cfg, ipou_free_item);
}


/*
 *
 * 	Config options
 *
 */

static void ipou_parse_debug(const struct ipou_cfg_item *item);
static void ipou_parse_log_to(const struct ipou_cfg_item *item);
static void ipou_parse_config_file(const struct ipou_cfg_item *item);
static void ipou_parse_help(const struct ipou_cfg_item *item);
static void ipou_parse_path_mtu(const struct ipou_cfg_item *item);
static void ipou_parse_server_addr(const struct ipou_cfg_item *item);
static void ipou_parse_server_port(const struct ipou_cfg_item *item);
static void ipou_parse_tun_addr4(const struct ipou_cfg_item *item);
static void ipou_parse_tun_addr6(const struct ipou_cfg_item *item);
static void ipou_parse_tun_name(const struct ipou_cfg_item *item);
static void ipou_parse_op_mode(const struct ipou_cfg_item *item);
static void ipou_parse_pool4(const struct ipou_cfg_item *item);
static void ipou_parse_pool6(const struct ipou_cfg_item *item);
static void ipou_parse_routes4(const struct ipou_cfg_item *item);
static void ipou_parse_routes6(const struct ipou_cfg_item *item);
static void ipou_parse_max_clients(const struct ipou_cfg_item *item);
static void ipou_parse_log_pkts(const struct ipou_cfg_item *item);

/* Array must be in alphabetical order for binary search */
static const struct ipou_cfg_opt ipou_cfg_opts[] = {
	{
		.name		= "client",
		.desc		= "client mode",
		.parse_fn	= ipou_parse_op_mode,
		.early		= 0,
		.file		= 1,
		.value		= 0,
		.server		= 0,
		.client		= 1,
		.required	= 1
	},
	{
		.name		= "config-file",
		.desc		= "configuration file",
		.parse_fn	= ipou_parse_config_file,
		.early		= 0,
		.file		= 0,
		.value		= 1,
		.server		= 1,
		.client		= 1,
		.required	= 0
	},
	{
		.name		= "connect-port",
		.desc		= "connect port",
		.parse_fn	= ipou_parse_server_port,
		.early		= 0,
		.file		= 1,
		.value		= 1,
		.server		= 0,
		.client		= 1,
		.required	= 0
	},
	{
		.name		= "connect-server",
		.desc		= "connect server",
		.parse_fn	= ipou_parse_server_addr,
		.early		= 0,
		.file		= 1,
		.value		= 1,
		.server		= 0,
		.client		= 1,
		.required	= 1
	},
	{
		.name		= "debug",
		.desc		= "enable debugging",
		.parse_fn	= ipou_parse_debug,
		.early		= 1,
		.file		= 1,
		.value		= 0,
		.server		= 1,
		.client		= 1,
		.required	= 0
	},
	{
		.name		= "help",
		.desc		= "print this message",
		.parse_fn	= ipou_parse_help,
		.early		= 1,
		.file		= 0,
		.value		= 0,
		.server		= 1,
		.client		= 1,
		.required	= 0
	},
	{
		.name		= "ipv4-pool-base",
		.desc		= "IPv4 address pool base",
		.parse_fn	= ipou_parse_pool4,
		.early		= 0,
		.file		= 1,
		.value		= 1,
		.server		= 1,
		.client		= 0,
		.required	= 0
	},
	{
		.name		= "ipv4-routes",
		.desc		= "additional IPv4 routes",
		.parse_fn	= ipou_parse_routes4,
		.early		= 0,
		.file		= 1,
		.value		= 1,
		.server		= 1,
		.client		= 0,
		.required	= 0
	},
	{
		.name		= "ipv4-tun-address",
		.desc		= "tunnel interface IPv4 address (CIDR)",
		.parse_fn	= ipou_parse_tun_addr4,
		.early		= 0,
		.file		= 1,
		.value		= 1,
		.server		= 1,
		.client		= 0,
		.required	= 0
	},
	{
		.name		= "ipv6-pool-base",
		.desc		= "IPv6 address pool base",
		.parse_fn	= ipou_parse_pool6,
		.early		= 0,
		.file		= 1,
		.value		= 1,
		.server		= 1,
		.client		= 0,
		.required	= 0
	},
	{
		.name		= "ipv6-routes",
		.desc		= "additional IPv6 routes",
		.parse_fn	= ipou_parse_routes6,
		.early		= 0,
		.file		= 1,
		.value		= 1,
		.server		= 1,
		.client		= 0,
		.required	= 0
	},
	{
		.name		= "ipv6-tun-address",
		.desc		= "tunnel interface IPv6 address (CIDR)",
		.parse_fn	= ipou_parse_tun_addr6,
		.early		= 0,
		.file		= 1,
		.value		= 1,
		.server		= 1,
		.client		= 0,
		.required	= 0
	},
	{
		.name		= "listen-address",
		.desc		= "listen address",
		.parse_fn	= ipou_parse_server_addr,
		.early		= 0,
		.file		= 1,
		.value		= 1,
		.server		= 1,
		.client		= 0,
		.required	= 0
	},
	{
		.name		= "listen-port",
		.desc		= "listen port",
		.parse_fn	= ipou_parse_server_port,
		.early		= 0,
		.file		= 1,
		.value		= 1,
		.server		= 1,
		.client		= 0,
		.required	= 0
	},
	{
		.name		= "log-packets",
		.desc		= "enable packet logging",
		.parse_fn	= ipou_parse_log_pkts,
		.early		= 0,
		.file		= 1,
		.value		= 0,
		.server		= 1,
		.client		= 1,
		.required	= 0
	},
	{
		.name		= "log-to",
		.desc		= "log message destination",
		.parse_fn	= ipou_parse_log_to,
		.early		= 1,
		.file		= 1,
		.value		= 1,
		.server		= 1,
		.client		= 1,
		.required	= 0
	},
	{
		.name		= "max-clients",
		.desc		= "maximum number of clients",
		.parse_fn	= ipou_parse_max_clients,
		.early		= 0,
		.file		= 1,
		.value		= 1,
		.server		= 1,
		.client		= 0,
		.required	= 0
	},
	{
		.name		= "path-mtu",
		.desc		= "network path MTU",
		.parse_fn	= ipou_parse_path_mtu,
		.early		= 0,
		.file		= 1,
		.value		= 1,
		.server		= 1,
		.client		= 0,
		.required	= 0
	},
	{
		.name		= "server",
		.desc		= "server mode",
		.parse_fn	= ipou_parse_op_mode,
		.early		= 0,
		.file		= 1,
		.value		= 0,
		.server		= 1,
		.client		= 0,
		.required	= 0
	},
	{
		.name		= "tun-name",
		.desc		= "tunnel interface name (or template)",
		.parse_fn	= ipou_parse_tun_name,
		.early		= 0,
		.file		= 1,
		.value		= 1,
		.server		= 1,
		.client		= 1,
		.required	= 0
	}
};
_Static_assert(sizeof ipou_cfg_opts / sizeof ipou_cfg_opts[0]
		== IPOU_CFG_OPTS_COUNT, "IPOU_CFG_OPTS_COUNT incorrect");


/*
 *
 *	Config option parsing
 *
 */

__attribute__((noreturn))
static void ipou_invalid_value(const struct ipou_cfg_item *const item,
			       const char *restrict const reason)
{
	IPOU_FATAL("Invalid config option value: %s: %s",
		   ipou_fmt_item2(item), reason);
}

__attribute__((noreturn))
static void ipou_conflicting_opts(const struct ipou_cfg_item *restrict const a,
				  const struct ipou_cfg_item *restrict const b)
{
	IPOU_FATAL("Conflicting config options: %s and %s",
		   ipou_fmt_item2(a), ipou_fmt_item2(b));
}

static void ipou_parse_debug(const struct ipou_cfg_item *const item
							__attribute__((unused)))
{
	ipou_debug = 1;
}

static void ipou_parse_log_pkts(const struct ipou_cfg_item *const itme
							__attribute__((unused)))
{
	ipou_log_pkts = 1;
}

static void ipou_parse_server_addr(const struct ipou_cfg_item *const item)
{
	static const struct in6_addr template = {
		.s6_addr = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00
		}
	};

	struct in_addr addr4;

	if (inet_pton(AF_INET6, item->value, &ipou_server.sin6.sin6_addr)
			!= 1) {

		if (inet_pton(AF_INET, item->value, &addr4) != 1) {
			ipou_invalid_value(item,
					   "not a valid IPv4 or IPv6 address");
		}

		ipou_server.sin6.sin6_addr = template;
		memcpy(&ipou_server.sin6.sin6_addr.s6_addr[12],
		       &addr4, sizeof addr4);
	}
}

static void ipou_parse_ip6(const struct ipou_cfg_item *const item,
			   struct in6_addr *const dst)
{
	if (inet_pton(AF_INET6, item->value, dst) != 1)
		ipou_invalid_value(item, "not a valid IPv6 address");
}

static void ipou_parse_pool6(const struct ipou_cfg_item *const item)
{
	ipou_parse_ip6(item, &ipou_pool6);
}

static void ipou_parse_ip4(const struct ipou_cfg_item *const item,
			   struct in_addr *const dst)
{
	if (inet_pton(AF_INET, item->value, dst) != 1)
		ipou_invalid_value(item, "not a valid IPv4 address");
}

static void ipou_parse_pool4(const struct ipou_cfg_item *const item)
{
	ipou_parse_ip4(item, &ipou_pool4);
}

static void ipou_parse_op_mode(const struct ipou_cfg_item *const item)
{
	const struct ipou_cfg_item *conflicting;

	if (ipou_mode != IPOU_MODE_UNSET) {

		if (ipou_mode == IPOU_MODE_SERVER)
			conflicting = ipou_get_item("server");
		else
			conflicting = ipou_get_item("client");

		IPOU_ASSERT(conflicting != NULL);

		ipou_conflicting_opts(conflicting, item);
	}

	if (strcmp(item->opt->name, "server") == 0)
		ipou_mode = IPOU_MODE_SERVER;
	else
		ipou_mode = IPOU_MODE_CLIENT;
}

static int ipou_parse_int(const char *const s)
{
	long value;
	char *endptr;

	errno = 0;
	value = strtol(s, &endptr, 10);

	if (errno != 0 || *endptr != 0 || value <= INT_MIN || value > INT_MAX)
		return INT_MIN;

	return value;
}


static int ipou_parse_int_item(const struct ipou_cfg_item *const item,
			       const int min, const int max)
{
	char *reason;
	int value;

	value = ipou_parse_int(item->value);

	if (value < min || value > max) {
		reason = IPOU_ASPRINTF("not an integer between %d and %d",
				       min, max);
		ipou_invalid_value(item, reason);
	}

	return value;
}

static void ipou_parse_max_clients(const struct ipou_cfg_item *const item)
{
	ipou_max_clients = ipou_parse_int_item(item, 1, 200);
}

static void ipou_parse_path_mtu(const struct ipou_cfg_item *const item)
{
	/* 576 is minimum IPv4 MTU */
	ipou_path_mtu = ipou_parse_int_item(item, IPOU_MIN_PATH_MTU,
					    IPOU_MAX_PATH_MTU);
}

static void ipou_parse_server_port(const struct ipou_cfg_item *const item)
{
	ipou_server.sin6.sin6_port = htons(ipou_parse_int_item(item, 1, 65535));
}

static void ipou_parse_log_to(const struct ipou_cfg_item *const item)
{
	if (strcmp(item->value, "syslog") == 0)
		ipou_use_syslog = 1;
	else if (strcmp(item->value, "stderr") == 0)
		ipou_use_syslog = 0;
	else
		ipou_invalid_value(item, "must be 'stderr' or 'syslog'");
}

static void ipou_parse_config_file(const struct ipou_cfg_item *const item)
{
	ipou_cfg_file = item->value;
}

static void ipou_parse_tun_name(const struct ipou_cfg_item *const item)
{
	size_t size;

	size = strlen(item->value) + 1;

	if (size <= 1)
		ipou_invalid_value(item, "name/template too short");

	if (size > IFNAMSIZ)
		ipou_invalid_value(item, "name/template too long");

	memcpy(ipou_tun_name, item->value, size);
}

static void ipou_parse_help(const struct ipou_cfg_item *const item
					__attribute__((unused)))
{
	const struct ipou_cfg_opt *opt;
	unsigned int i;

	puts("IP over UDP tunnel daemon (ipoud) options:");

	for (i = 0; i < IPOU_CFG_OPTS_COUNT; ++i) {

		opt = &ipou_cfg_opts[i];

		printf("  %20s%s\t%s", opt->name,
		       opt->value ? "=..." : "    ", opt->desc);

		if (opt->server && opt->client)
			putchar('\n');
		else if (opt->server)
			puts(" (server mode only)");
		else
			puts(" (client mode only)");
	}

	exit(EXIT_SUCCESS);
}

static int ipou_net_pton6(const char *restrict const pres,
			  struct in6_addr *const addr)
{
	char *restrict src;
	int prefix, nchar;

	if (sscanf(pres, "%m[0-9a-fA-F:.]/%n", &src, &nchar) != 1) {
		errno = ENOENT;
		return -1;
	}

	if (inet_pton(AF_INET6, src, addr) != 1) {
		errno = ENOENT;
		return -1;
	}

	prefix = ipou_parse_int(pres + nchar);

	if (prefix < 0) {
		errno = ENOENT;
		return -1;
	}

	if (prefix > 128) {
		errno = EMSGSIZE;
		return -1;
	}

	return prefix;
}

static void ipou_parse_tun_addr4(const struct ipou_cfg_item *const item)
{
	int pfx_len;

	pfx_len = inet_net_pton(AF_INET, item->value,
				&ipou_tun_addr4, sizeof ipou_tun_addr4);
	if (pfx_len < 0) {
		ipou_invalid_value(item, "not a valid IPv4 address and "
						"prefix length");
	}

	if (strchr(item->value, '/') == NULL)
		ipou_invalid_value(item, "prefix length not specified");

	if (pfx_len < 24 || pfx_len > 31) {
		ipou_invalid_value(item,
				   "IPv4 prefix length not between 24 and 31");
	}

	ipou_tun_pfx4 = pfx_len;
	ipou_tun_netmask4 = ipou_mknetmask4(ipou_tun_pfx4);
	ipou_tun_netaddr4 = ipou_mknetaddr4(ipou_tun_addr4, ipou_tun_netmask4);

	if (ipou_is_netaddr4(ipou_tun_addr4, ipou_tun_netmask4)) {
		IPOU_WARNING("'ipv4-tun-address' (%s) is a network address",
			     item->value);
	}

	if (ipou_is_netcast4(ipou_tun_addr4, ipou_tun_netmask4)) {
		IPOU_WARNING("'ipv4-tun-address' (%s) is a broadcast address",
			     item->value);
	}
}

static void ipou_parse_tun_addr6(const struct ipou_cfg_item *const item)
{
	int pfx_len;

	if ((pfx_len = ipou_net_pton6(item->value, &ipou_tun_addr6)) < 0) {
		ipou_invalid_value(item, "not a valid IPv6 address and "
						"prefix length");
	}

	/*
	 * Don't change minimum prefix length; see ipou_validate_server_ipv6()
	 */
	if (pfx_len < 64 || pfx_len > 127) {
		ipou_invalid_value(item,
				   "IPv6 prefix length not between 64 and 127");
	}

	ipou_tun_pfx6 = pfx_len;
	ipou_mknetmask6(ipou_tun_pfx6, &ipou_tun_netmask6);
	ipou_mknetaddr6(&ipou_tun_addr6, &ipou_tun_netmask6,
			&ipou_tun_netaddr6);

	if (ipou_is_netaddr6(&ipou_tun_addr6, &ipou_tun_netmask6)) {
		IPOU_WARNING("'ipv6-tun-address' (%s) is a network address",
			     item->value);
	}
}

static void ipou_parse_routes6(const struct ipou_cfg_item *const item)
{
	struct ipou_cfg_route6 *route6;
	struct in6_addr netmask;
	char *route, *reason;
	int nchar, total, pfx_len;
	uint8_t count;

	total = 0;
	count = 0;

	while (sscanf(item->value + total, "%m[^,]%n", &route, &nchar) == 1) {

		route6 = IPOU_ZALLOC(sizeof *route6);

		if ((route6->count = ++count) > IPOU_MAX_ROUTES)
			ipou_invalid_value(item, "too many IPv6 routes");

		if ((pfx_len = ipou_net_pton6(route, &route6->dest)) < 0)
			break;

		IPOU_ASSERT(pfx_len <= 128);
		route6->pfx_len = pfx_len;
		ipou_mknetmask6(route6->pfx_len, &netmask);

		if (!ipou_is_netaddr6(&route6->dest, &netmask)) {
			reason = IPOU_ASPRINTF(
					"not a valid IPv6 network address: %s",
					route);
			ipou_invalid_value(item, reason);
		}

		route6->next = ipou_cfg_routes6;
		ipou_cfg_routes6 = route6;

		free(route);
		total += nchar;

		if (item->value[total] == 0)
			return;

		++total;
	}

	reason = IPOU_ASPRINTF("failed to parse IPv6 network address from '%s'",
			       item->value + total);
	ipou_invalid_value(item, reason);
}

static void ipou_parse_routes4(const struct ipou_cfg_item *const item)
{
	struct ipou_cfg_route4 *route4;
	struct in_addr netmask;
	char *route, *reason;
	int nchar, total, pfx_len;
	uint8_t count;

	total = 0;
	count = 0;

	while (sscanf(item->value + total, "%m[^,]%n", &route, &nchar) == 1) {

		route4 = IPOU_ZALLOC(sizeof *route4);

		if ((route4->count = ++count) > IPOU_MAX_ROUTES)
			ipou_invalid_value(item, "too many IPv4 routes");

		pfx_len = inet_net_pton(AF_INET, route,
					&route4->dest, sizeof route4->dest);
		if (pfx_len < 0)
			break;

		IPOU_ASSERT(pfx_len <= 32);
		route4->pfx_len = pfx_len;
		route4->count = ++count;

		netmask = ipou_mknetmask4(route4->pfx_len);

		if (!ipou_is_netaddr4(route4->dest, netmask)) {
			reason = IPOU_ASPRINTF(
					"not a valid IPv4 network address: %s",
					route);
			ipou_invalid_value(item, reason);
		}

		route4->next = ipou_cfg_routes4;
		ipou_cfg_routes4 = route4;

		free(route);
		total += nchar;

		if (item->value[total] == 0)
			return;

		++total;
	}

	reason = IPOU_ASPRINTF("failed to parse IPv4 network address from '%s'",
			       item->value + total);
	ipou_invalid_value(item, reason);
}
