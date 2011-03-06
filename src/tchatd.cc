#include <iostream>

#include "tchatd.hh"
#include "user.hh"
#include "network.hh"
#include "commands.hh"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include <math.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <stdarg.h>

using namespace std;

// primary subroutines from main

void sub_options(int argc, char **argv);
void sub_config();
void sub_work();
void sub_test();
void sub_signals();
void sub_atexit();

void sub_load();
void sub_load_users();
void sub_load_sockets();
void sub_load_commands();

// sub_save and sub_cleanup is registered atexit()

void sub_save();

void sub_cleanup();
void sub_cleanup_temp();
void sub_cleanup_sockets();

// systems stuff

void sighandler(int);
void version();
void usage(const char *prog);
int main(int argc, char **argv);

int randomrange(int a, int b) {
	double d = (b - a + 1) * (double)random() / (RAND_MAX + 1.0);
	int c = (int)floor(d);
	return c + a;
}

int main(int argc, char **argv) {

	// register signal handlers

	sub_signals();

	// register atexit cleanup

	sub_atexit();

	// check options

	sub_options(argc, argv);

	// load configuration

	sub_config();

	// load state

	sub_load();

	// start main event loop

	if(config::test)
		sub_test();
	else
		sub_work();

	// exit successfully

	exit(EXIT_SUCCESS);
}

void sighandler(int signo) {

	if(signo == SIGINT) {
		DEBUG_MESSAGE2("interrupt caught");
		exit(EXIT_SUCCESS);
	} else if(signo == SIGHUP) {
		DEBUG_MESSAGE2("hang-up caught");
		exit(EXIT_SUCCESS);
	} else if(signo == SIGALRM) {
		DEBUG_MESSAGE2("alarm caught");
	} else if(signo == SIGUSR1) {
		DEBUG_MESSAGE2("user signal 1 caught");
	} else if(signo == SIGUSR2) {
		DEBUG_MESSAGE2("user signal 2 caught");
	}
}

void handle_error(const char *str) {
	perror(str);
	exit(EXIT_FAILURE);
}


void version() {
	printf("%s %s\n", PROGRAM, VERSION);
}

void usage(const char *prog) {

	const int width = 15;

	char str[80];

	putchar('\n');

	version();

	printf("\nusage: %s [options]\n\n", prog);

	printf("\t%-*s%s (default: %d)\n", width, "-T num", "maximum connections", config::connections);
	printf("\t%-*s%s (default: %d)\n", width, "-B backlog", "maximum connection backlog", config::backlog);
	printf("\t%-*s%s (default: %d)\n", width, "-P port", "source tcp port", config::port);
	printf("\t%-*s%s (default: %s)\n", width, "-A ipaddr", "source ip address", config::ip.s_addr == INADDR_ANY ? "any" : inet_ntop(AF_INET, &config::ip, str, sizeof(str)));
	printf("\t%-*s%s (default: %d)\n", width, "-c maxcmdsz", "maximum command size", config::maxcmdsz);
	printf("\t%-*s%s (default: %d)\n", width, "-n maxusersz", "maximum username length", config::maxusersz);
	printf("\t%-*s%s (default: %s)\n", width, "-M motd", "message of the day", config::motd.c_str());
	printf("\t%-*s%s (default: %s)\n", width, "-S servername", "server name", config::servername.c_str());
	printf("\t%-*s%s\n", width, "-v", "verbose");
	printf("\t%-*s%s\n", width, "-V", "version");
	printf("\t%-*s%s\n", width, "-D", "debug mode");
	printf("\t%-*s%s\n", width, "-@", "test mode");
	printf("\t%-*s%s\n\n", width, "-h", "help");
}

void sub_signals() {
   signal(SIGINT, sighandler);
   signal(SIGHUP, sighandler);
   signal(SIGALRM, sighandler);
   signal(SIGUSR1, sighandler);
   signal(SIGUSR2, sighandler);
}

void sub_atexit() {
   atexit(sub_cleanup);
   atexit(sub_save);
}

void sub_options(int argc, char **argv) {

	DEBUG_MESSAGE;

	int opt;

	while ((opt = getopt(argc, argv, "vVD@hP:T:A:B:c:n:M:S:")) != -1) {

		switch (opt) {

			case 'A':

				if(!inet_aton(optarg, &config::ip)) {
					puts("invalid ip address");
					exit(EXIT_FAILURE);
				}
				break;

			case 'B':

				config::backlog = strtoul(optarg, NULL, 0);
				break;

			case 'P':

				config::port = strtoul(optarg, NULL, 0);
				break;

			case 'n':

				config::maxusersz = strtoul(optarg, NULL, 0);
				break;

			case 'M':

				config::motd = optarg;
				break;

			case 'S':

				config::servername = optarg;
				break;

			case 'c':

				config::maxcmdsz = strtoul(optarg, NULL, 0);
				break;

			case 'T':

				config::connections = strtoul(optarg, NULL, 0);
				break;

			case 'v':

				config::verbose = true;
				break;

			case 'V':

				version();
				exit(EXIT_SUCCESS);

			case 'D':

				config::debug = true;
				break;

			case '@':

				config::test = true;
				break;

			case 'h':
			case '?':

				usage(argv[0]);
				exit(EXIT_FAILURE);
		}
	}
}

void sub_config() {

	DEBUG_MESSAGE;

	const int width = 25;

	char str[80];

	srandom(getpid() + time(NULL));

	if(config::port > 65535) {
		puts("port out of range (1-65535)");
		exit(EXIT_FAILURE);
	}

	if(config::maxusersz > MAXUSERSZ) {
		printf("maximum username length cannot exceed %d bytes\n", MAXUSERSZ);
		exit(EXIT_FAILURE);
	}

	if(config::connections > FD_SETSIZE) {
		printf("maximum connections cannot exceed %d\n", FD_SETSIZE);
		exit(EXIT_FAILURE);
	}

	if(config::backlog > SOMAXCONN) {
		printf("maximum connection backlog cannot exceed %d\n", SOMAXCONN);
		exit(EXIT_FAILURE);
	}

	if(config::maxcmdsz > MAXCMDSZ) {
		printf("maximum command size cannot exceed %d bytes\n", MAXCMDSZ);
		exit(EXIT_FAILURE);
	}

	if(config::verbose) {
		printf("%*s | %s:%d\n", width, "will bind to", config::ip.s_addr == INADDR_ANY ? "any" : inet_ntop(AF_INET, &config::ip, str, sizeof(str)), config::port);
		printf("%*s | %d\n", width, "maximum connections", config::connections);
		printf("%*s | %d\n", width, "connection backlog", config::backlog);
		printf("%*s | %d bytes\n", width, "maximum command size", config::maxcmdsz);
		printf("%*s | %d bytes\n", width, "maximum username length", config::maxusersz);
		printf("%*s | %s\n", width, "server name", config::servername.c_str());
		printf("%*s | %s\n", width, "message of the day", config::motd.c_str());
	}
}

void sub_load_users() {
	DEBUG_MESSAGE;
	// FIXME: load users
}

void sub_load_sockets() {

	DEBUG_MESSAGE;

	struct sockaddr_in sin;

	// open socket

	state::sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(state::sd == -1)
		handle_error("socket");

	// bind socket

	memset(&sin, 0, sizeof(sin));

	sin.sin_family = AF_INET;
	sin.sin_addr = config::ip;
	sin.sin_port = htons((unsigned short)config::port);

	if(bind(state::sd, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		handle_error("bind");

	if(listen(state::sd, config::backlog) == -1)
		handle_error("listen");
}

void sub_load_commands() {

	DEBUG_MESSAGE;

	for(unsigned int i = 0; command::command_pairs[i].command_name != NULL; i++)
		command::calls[command::command_pairs[i].command_name] = command::command_pairs[i].command_fptr;

	for(unsigned int i = 0; command::msg_pairs[i].msg_code != NULL; i++)
		command::messages[command::msg_pairs[i].msg_code] = command::msg_pairs[i].msg_str;
}

void sub_load() {

	DEBUG_MESSAGE;

	sub_load_users();

	sub_load_sockets();

	sub_load_commands();

	// connect to listening interface (socket/bind/listen)
}

void sub_work() {

	DEBUG_MESSAGE;

	while(!state::done) {

		// watch all file descriptors for read or exception work

		int nfds;
		int n;

		// init the FD SETs

		FD_ZERO(&state::rfds);
		FD_SET(state::sd, &state::rfds);
		nfds = state::sd;
		for(fdset_t::iterator fd_itr = state::fdset.begin(); fd_itr != state::fdset.end(); fd_itr++) {
			FD_SET(*fd_itr, &state::rfds);
			if(*fd_itr > nfds)
				nfds = *fd_itr;
		}

		// do select

		do {
			struct timeval tv = { 60, 0 };
			n = select(nfds + 1, &state::rfds, NULL, NULL, &tv);
		} while(n == -1 && errno == EINTR);

		switch(n) {

			case -1:

				handle_error("select");
				break;

			case 0:

				DEBUG_MESSAGE2("no data");
				break;

			default:

				// handle various read types

				if(FD_ISSET(state::sd, &state::rfds)) {
					n--;
					do_connect();
				}

				if(n > 0)
					do_read_all();
		}
	}
}

void sub_save() {

	DEBUG_MESSAGE;

   for(userlist_t::iterator uitr = state::users.begin(); uitr != state::users.end(); uitr++) {
      cout << (*uitr)->serialize();
   }
}

void sub_cleanup_sockets() {

	DEBUG_MESSAGE;

	if(state::sd >= 0)
		close(state::sd);

	fdset_t::iterator fd_itr = state::fdset.begin();

	while(fd_itr != state::fdset.end()) {
		int fd = *fd_itr++; // kinda weird, but the iterator is unhappy when the item gets removed
		do_disconnect(fd);
	}
}

void sub_cleanup_temp() {
	DEBUG_MESSAGE;
}

void sub_cleanup() {

	DEBUG_MESSAGE;

	sub_cleanup_sockets();

	sub_cleanup_temp();
}

void sub_test() {

   const char *usernames[] = { "fucker", "sucker", "shitter", "bob", NULL };

   for(const char **username = usernames; *username != NULL; username++) {
      if(!user::exists(*username)) {
         printf("creating new user %s\n", *username);
         new user(*username, *username);
      }
   }

   const nodelist_t& nl = (*state::users.begin())->get_nodes();

   for(nodelist_t::const_iterator itr = nl.begin(); itr != nl.end(); itr++)
      printf("id = %d -- distance = %d\n", itr->id, itr->distance);

}
