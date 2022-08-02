#include "ipoud.h"

#include <arpa/inet.h>
#include <limits.h>
#include <stdarg.h>

_Bool ipou_use_syslog;  /* auto-detected */

void ipou_log(const int level, const char *const format, ...)
{
	va_list ap;
	size_t fmt_len;

	va_start(ap, format);

	if (ipou_use_syslog) {
		vsyslog(level, format, ap);
	}
	else {
		vfprintf(stderr, format, ap);
		fmt_len = strlen(format);
		if (fmt_len > 0 && format[fmt_len - 1] != '\n')
			fputc('\n', stderr);
	}

	va_end(ap);
}

void *ipou_zalloc(const size_t size, const char *restrict const file,
		  const int line)
{
	void *buf;

	if ((buf = calloc(1, size)) == NULL) {

		ipou_log(LOG_ERR, "ERR: %s:%d: Failed to allocate %zu bytes",
			 file, line, size);
		exit(EXIT_FAILURE);
	}

	return buf;
}

char *ipou_strdup(const char *const restrict s, const char *const restrict file,
		  const int line)
{
	size_t size;
	char *dupe;

	size = strlen(s);
	IPOU_ASSERT(size < SIZE_MAX);
	++size;

	if ((dupe = malloc(size)) == NULL) {

		ipou_log(LOG_ERR, "ERR: %s:%d: Failed to allocate %zu bytes",
			 file, line, size);
		exit(EXIT_FAILURE);
	}

	memcpy(dupe, s, size);

	return dupe;
}

char *ipou_asprintf(const char *const restrict file, const int line,
		    const char *const restrict format, ...)
{
	ssize_t size;
	char *s;
	va_list ap;

	va_start(ap, format);

	size = vsnprintf(NULL, 0, format, ap);
	IPOU_ASSERT(size >= 0);
	IPOU_ASSERT(size < SSIZE_MAX);
	++size;

	va_end(ap);
	va_start(ap, format);

	if ((s = malloc(size)) == NULL) {

		ipou_log(LOG_ERR, "ERR: %s:%d: Failed to allocate %zu bytes",
			 file, line, size);
		exit(EXIT_FAILURE);
	}

	IPOU_ASSERT(vsnprintf(s, size, format, ap) == size - 1);
	va_end(ap);

	return s;
}

const char *ipou_ntop(const struct in6_addr *const addr,
		      char *restrict const dst)
{
	struct in_addr addr4;

	if (IN6_IS_ADDR_V4MAPPED(addr)) {
		memcpy(&addr4, &addr->s6_addr[12], sizeof addr4);
		return inet_ntop(AF_INET, &addr4, dst, INET6_ADDRSTRLEN);
	}

	return inet_ntop(AF_INET6, addr, dst, INET6_ADDRSTRLEN);
}

const char *ipou_sock_ntop(const struct sockaddr_in6 *const addr,
			   char *restrict const dst)
{
	char addrbuf[INET6_ADDRSTRLEN];
	const char *fmt;

	if (IN6_IS_ADDR_V4MAPPED(&addr->sin6_addr))
		fmt = "%s:%" PRIu16;
	else
		fmt = "[%s]:%" PRIu16;

	sprintf(dst, fmt, ipou_ntop(&addr->sin6_addr, addrbuf),
		ntohs(addr->sin6_port));

	return dst;
}
