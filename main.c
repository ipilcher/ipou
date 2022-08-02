#include "ipoud.h"

#include <errno.h>

union ipou_buf_t ipou_buf;
volatile sig_atomic_t ipou_exit_flag = 0;

static void ipou_catch_signal(const int signum)
{
	_Static_assert(SIGINT <= SIG_ATOMIC_MAX,
		       "SIGINT is not a valid sig_atomic_t");
	_Static_assert(SIGTERM <= SIG_ATOMIC_MAX,
		       "SIGTERM is not a valid sig_atomic_t");

	ipou_exit_flag = signum;
}

static void ipou_signal_setup(sigset_t *const oldmask)
{
	struct sigaction sa;
	sigset_t mask;

	if (sigemptyset(&mask) != 0)
		IPOU_PFATAL("sigemptyset");
	if (sigaddset(&mask, SIGTERM) != 0)
		IPOU_PFATAL("sigaddset(SIGTERM)");
	if (sigaddset(&mask, SIGINT) != 0)
		IPOU_PFATAL("sigaddset(SIGINT)");

	sa.sa_handler = ipou_catch_signal;
	sa.sa_mask = mask;
	sa.sa_flags = SA_RESETHAND;

	if (sigprocmask(SIG_BLOCK, &mask, oldmask) != 0)
		IPOU_PFATAL("sigprocmask");

	if (sigaction(SIGTERM, &sa, NULL) != 0)
		IPOU_PFATAL("sigaction(SIGTERM)");
	if (sigaction(SIGINT, &sa, NULL) != 0)
		IPOU_PFATAL("sigaction(SIGINT)");
}

int main(const int argc __attribute__((unused)), char **const argv)
{
	static const struct timespec timeout = {
		.tv_sec		= 30,
		.tv_nsec	= 0
	};

	struct pollfd pfds[2];
	sigset_t sigmask;

	ipou_get_config(argv);
	ipou_netlink_init();
	ipou_icmp_init();

	if (ipou_mode == IPOU_MODE_SERVER)
		ipou_server_setup();
	else
		ipou_client_setup();

	ipou_netlink_cleanup();

	ipou_signal_setup(&sigmask);  /* blocks SIGTERM & SIGINT */
	pfds[0].fd = ipou_socket_fd;
	pfds[0].events = POLLIN;
	pfds[1].fd = ipou_tun_fd;
	pfds[1].events = POLLIN;

	while (ipou_exit_flag == 0) {

		if (ppoll(pfds, 2, &timeout, &sigmask) < 0) {
			if (errno == EINTR)
				continue;
			IPOU_PFATAL("ppoll");
		}

		if (ipou_mode == IPOU_MODE_SERVER)
			ipou_server_process(pfds);
		else
			ipou_client_process(pfds);
	}

	if (ipou_exit_flag == SIGINT)
		IPOU_INFO("Got SIGINT; shutting down");
	else if (ipou_exit_flag == SIGTERM)
		IPOU_INFO("Got SIGTERM; shutting down");
	else if (ipou_exit_flag == IPOU_CLIENT_EXIT_GOODBYE)
		IPOU_INFO("Got server GOODBYE; shutting down");
	else if (ipou_exit_flag == IPOU_CLIENT_EXIT_TIMEOUT)
		IPOU_INFO("Server timeout; shutting down");
	else if (ipou_exit_flag == IPOU_CLIENT_EXIT_RENEG)
		IPOU_INFO("Session renegotiation failed; shutting down");
	else
		IPOU_ABORT("Unreachable code");

	if (ipou_mode == IPOU_MODE_SERVER)
		ipou_server_shutdown();
	else
		ipou_client_shutdown();

	return EXIT_SUCCESS;
}

