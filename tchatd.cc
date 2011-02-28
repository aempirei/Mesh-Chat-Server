#include <sstream>

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
void sub_test();
void sub_work();

void sub_load();
void sub_load_users();
void sub_load_friends();
void sub_load_routes();
void sub_load_sockets();

// sub_save and sub_cleanup is registered atexit()

void sub_save_users();
void sub_save_friends();
void sub_save_routes();
void sub_save();

void sub_cleanup();
void sub_cleanup_temp();
void sub_cleanup_sockets();

// other crap -- some of this belongs in network.cc

void do_connect();
void do_read_all();
void do_read(int fd);
void do_handle_input(int fd);

void sighandler(int);

int randomrange(int a, int b) {
	double d = (b - a + 1) * (double)random() / (RAND_MAX + 1.0);
	int c = (int)floor(d);
	return c + a;
}

int main(int argc, char **argv) {

	// register save, cleanup and signal handling

	signal(SIGINT, sighandler);
	signal(SIGHUP, sighandler);
	signal(SIGALRM, sighandler);
	signal(SIGUSR1, sighandler);
	signal(SIGUSR2, sighandler);

	atexit(sub_cleanup);
	atexit(sub_save);

	// check options

	sub_options(argc, argv);

	// load configuration

	sub_config();

	// load state

	sub_load();

	// test if option is set

	if(config::test)
		sub_test();

	// start main event loop

	sub_work();

	exit(EXIT_SUCCESS);
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

void sighandler(int signo) {

	if(signo == SIGINT) {
		config::debug && puts("interrupt caught");
		exit(EXIT_SUCCESS);
	} else if(signo == SIGHUP) {
		config::debug && puts("hang-up caught");
		exit(EXIT_SUCCESS);
	} else if(signo == SIGALRM) {
		config::debug && puts("alarm caught");
	} else if(signo == SIGUSR1) {
		config::debug && puts("user signal 1 caught");
	} else if(signo == SIGUSR2) {
		config::debug && puts("user signal 2 caught");
	}
}

void handle_error(const char *str) {
	perror(str);
	exit(EXIT_FAILURE);
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

void sub_load_friends() {
	DEBUG_MESSAGE;
	// FIXME: load friends
}

void sub_load_routes() {
	DEBUG_MESSAGE;
	// FIXME: load routes
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

void sub_load_command() {

	DEBUG_MESSAGE;

	for(unsigned int i = 0; command::command_pairs[i].command_name != NULL; i++)
		command::calls[command::command_pairs[i].command_name] = command::command_pairs[i].command_fptr;

	for(unsigned int i = 0; command::msg_pairs[i].msg_code != NULL; i++)
		command::messages[command::msg_pairs[i].msg_code] = command::msg_pairs[i].msg_str;
}

void sub_load() {

	DEBUG_MESSAGE;

	sub_load_users();
	sub_load_friends();
	sub_load_routes();

	sub_load_sockets();

	sub_load_command();

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

				config::debug && puts("no data");
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

void do_connect() {

	DEBUG_MESSAGE;

	struct sockaddr_in sin;

	socklen_t sl = sizeof(sin);

	int fd = accept(state::sd, (struct sockaddr *)&sin, &sl);
	if(fd == -1)
		handle_error("accept");

	state::fdset.insert(fd);
	state::recvstreams[fd] = new stringstream(stringstream::binary|stringstream::out|stringstream::in);

	do_message(fd, MCSERVER, PROGRAM " " VERSION);
}

void do_read_all() {

	DEBUG_MESSAGE;

	fdset_t::iterator fd_itr = state::fdset.begin();

	while(fd_itr != state::fdset.end()) {
		// process each iterator for reading data, but make sure we get the iterators next position
		// before calling, since do_read() may disconnect an fd which will destroy the associated iterator
		int fd = *fd_itr++;
		if(FD_ISSET(fd, &state::rfds))
			do_read(fd);
	}
}

void do_read(int fd) {

	static char buf[4096];
	int n;

	DEBUG_PRINTF("reading up to %ld bytes from %d\n", (long)sizeof(buf), fd);

	do {
		n = recv(fd, (void *)buf, sizeof(buf), 0);
	} while(n == -1 && errno == EINTR);

	switch(n) {

		case -1:

			handle_error("recv");
			break;

		case 0:

			do_disconnect(fd);
			break;

		default:

			DEBUG_PRINTF("read %d bytes from %d\n", n, fd);

			state::recvstreams[fd]->write(buf, n);

			do_handle_input(fd);
	}
}

void do_unknown_command(int fd, const string& command, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("*** %s ( %d %s [ %ld ] %s )\n", __FUNCTION__, fd, command.c_str(), (long)params.size(), msg.c_str());

	do_message(fd, MCCMD, command.c_str());
}

void do_handle_line(int fd, const char *line) {

	DEBUG_PRINTF("processing line for %d : %s\n", fd, line);

	stringstream ss(line, stringstream::in | stringstream::out);

	string command;
	list<string> params;
	string msg;

	// a command line is a newline (0x10 '\n') terminated string of the form:
	// COMMAND PARAMS* (:MESSAGE)?

	// get the command

	ss >> skipws >> command >> ws;

	// get zero or more parameters

	while(!ss.eof() && ss.peek() != ':') {
		string next;
		ss >> next >> ws;
		params.push_back(next);
	}

	// get the optional message

	if(!ss.eof() && ss.peek() == ':') {
		stringbuf sb;
		ss.get();
		ss.get(sb);
		msg = sb.str();
	}

	// try to call the corresponding command

	commandmap_t::iterator command_itr = command::calls.find(command.c_str());

	if(command_itr == command::calls.end()) {
		do_unknown_command(fd,command,params,msg);
	} else {
		// if the command is legit, then tick the user if they are validated
		if(is_validated(fd))
			state::users_by_fd[fd]->tick();
		(command_itr->second)(fd,params,msg);
	}
}

void do_handle_input(int fd) {

	DEBUG_MESSAGE;

	char line[config::maxcmdsz];
	stringstream *ss = state::recvstreams[fd];
	stringbuf sb;

	while(!ss->eof()) {

		// process each line as a command
		// handle incomplete lines and lines that are too long

		ss->getline(line, config::maxcmdsz);

		if(ss->fail()) {

			if(!ss->eof()) {

				// a command was too long if FAIL without EOF so skip it

				ss->clear();
				ss->get(sb, '\n');

				if(ss->peek() == '\n')
					ss->get();

				config::debug && puts("command too long");
			}

		} else if(ss->good()) {

			do_handle_line(fd, line);

			// if connection was closed, then quickly leave since
			// the iterator for ss is no longer valid

			if(state::fdset.find(fd) == state::fdset.end())
				return;
		}

		// any time we read EOF then theres definitely no more data for now

	}

	ss->clear();

	if(ss->gcount() > 0) {

		// if data was read on the exit round then put it back

		ss->write(line, ss->gcount());
		config::debug && puts("not enough data");
	}
}

void sub_save_users() {
	DEBUG_MESSAGE;
	// FIXME: add save users
}

void sub_save_friends() {
	DEBUG_MESSAGE;
	// FIXME: add save friends
}

void sub_save_routes() {
	DEBUG_MESSAGE;
	// FIXME: add save routes
}

void sub_save() {

	DEBUG_MESSAGE;

	sub_save_users();
	sub_save_friends();
	sub_save_routes();
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

	user *u1 = new user("user1","pass");
	user *u2 = new user("user2","pass");
	user *u3 = new user("user3","pass");
	user *u4 = new user("user4","pass");
	user *u5 = new user("user5","pass");
	user *u6 = new user("user6","pass");

	u1->friends.insert(u2->id);
	u2->friends.insert(u1->id);

	u1->friends.insert(u3->id);
	u3->friends.insert(u1->id);

	u2->friends.insert(u4->id);
	u4->friends.insert(u2->id);

	u3->friends.insert(u4->id);
	u4->friends.insert(u3->id);

	u4->friends.insert(u5->id);
	u5->friends.insert(u4->id);

	u5->friends.insert(u6->id);
	u6->friends.insert(u5->id);

	nodelist_t nl = u1->get_nodes();

	for(nodelist_t::iterator itr = nl.begin(); itr != nl.end(); itr++)
		printf("id = %d -- distance = %d\n", itr->id, itr->distance);

	exit(EXIT_SUCCESS);
}
