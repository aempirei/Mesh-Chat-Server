#include <vector>
#include <list>
#include <map>
#include <set>
#include <string>
#include <iostream>
#include <sstream>

#include "tchatd.hh"

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
#include <errno.h>


#define PROGRAM "Topology Chat Server"
#define VERSION "1.0"
#define DEBUG_MESSAGE		DEBUG_MESSAGE2(__FUNCTION__)
#define DEBUG_MESSAGE2(a)	(option::debug && puts(a))

using namespace std;

void do_options(int argc, char **argv);
void do_config();
void do_load_users();
void do_load_friends();
void do_load_routes();
void do_load_sockets();
void do_send(int fd, const void *buf, size_t len, int flags);
void do_message(int fd, const char *msg_code, const char *msg);
void do_message(int fd, const char *msg_code);
void do_load();
void do_work();
void do_connect();
void do_disconnect(int fd);
void do_read_all();
void do_read(int fd);
void do_handle_input(int fd);
void do_save_users();
void do_save_friends();
void do_save_routes();
void do_save();
void do_cleanup_sockets();
void do_cleanup_temp();
void do_cleanup();

void handle_error(const char *str);

void sighandler(int);

struct str_compar {
	bool operator()(const char * str1, const char *str2) {
		return strcmp(str1, str2) < 0;
	}
};

struct strcase_compar {
	bool operator()(const char * str1, const char *str2) {
		return strcasecmp(str1, str2) < 0;
	}
};

struct uint_compar {
	bool operator()(const unsigned int uint1, const unsigned int uint2) {
		return uint1 < uint2;
	}
};

struct int_compar {
	bool operator()(const int uint1, const int uint2) {
		return uint1 < uint2;
	}
};

class user;

typedef set<int> fdset_t;
typedef list<user *> userlist_t;
typedef list<string> paramlist_t;
typedef set<unsigned int> friendset_t;

typedef void command_fn_t(int fd, const paramlist_t& params, const string& msg);
typedef map<const char *, command_fn_t *, strcase_compar> commandmap_t;
typedef map<const char *,const char *, strcase_compar> msgmap_t;

command_fn_t do_command_anti;
command_fn_t do_command_friend;
command_fn_t do_command_friends;
command_fn_t do_command_listen;
command_fn_t do_command_user;
command_fn_t do_command_pass;
command_fn_t do_command_ping;
command_fn_t do_command_pong;
command_fn_t do_command_quit;
command_fn_t do_command_radio;
command_fn_t do_command_say;
command_fn_t do_command_scan;
command_fn_t do_command_set;
command_fn_t do_command_tell;
command_fn_t do_command_vector;
command_fn_t do_command_whisper;
command_fn_t do_command_whois;

namespace command {

	struct command_name_fptr_pair {

		const char *command_name;
		const command_fn_t *command_fptr;

	} command_pairs[] = {

#define CUSER    "user"
#define CPASS    "pass"
#define CSET     "set"
#define CPING    "ping"
#define CPONG    "pong"
#define CFRIEND  "friend"
#define CANTI    "anti"
#define CLISTEN  "listen"
#define CSAY     "say"
#define CVECTOR  "vector"
#define CRADIO   "radio"
#define CWHISPER "whisper"
#define CTELL    "tell"
#define CWHOIS   "whois"
#define CSCAN    "scan"
#define CFRIENDS "friends"
#define CQUIT    "quit"

		{ CUSER   , do_command_user    }, // USER username
		{ CPASS   , do_command_pass    }, // PASS password
		{ CSET    , do_command_set     }, // SET property :value
		{ CPING   , do_command_ping    }, // PING :challenge
		{ CPONG   , do_command_pong    }, // PONG :response
		{ CFRIEND , do_command_friend  }, // FRIEND username
		{ CANTI   , do_command_anti    }, // ANTI username
		{ CLISTEN , do_command_listen  }, // LISTEN channel
		{ CSAY    , do_command_say     }, // SAY :message
		{ CVECTOR , do_command_vector  }, // VECTOR username :message
		{ CRADIO  , do_command_radio   }, // RADIO channel :message
		{ CWHISPER, do_command_whisper }, // WHISPER :message
		{ CTELL   , do_command_tell    }, // TELL username :message
		{ CWHOIS  , do_command_whois   }, // WHOIS username
		{ CSCAN   , do_command_scan    }, // SCAN
		{ CFRIENDS, do_command_friends }, // FRIENDS
		{ CQUIT   , do_command_quit    }, // QUIT
		{ NULL    , NULL               }
	};

	commandmap_t calls;

	struct msg_code_msg_pair {
		const char *msg_code;
		const char *msg_str;
	} msg_pairs[] = {

// information messages
#define MCSERVER   "000"
#define MCMOTD     "001"
#define MCNAME     "002"
#define MCCREATED  "003"
#define MCVERIFIED "004"

#define MCNEWUSER  "051"
#define MCNEWPASS  "052"

#define MCFRIEND   "061"
#define MCREQUEST  "062"
#define MCANTI     "063"
#define MCDISTANCE "064"
#define MCRREQUEST "065"
#define MCRANTI    "066"

#define MCBEGIN    "080"
#define MCEND      "081"

#define MCGOODBYE  "099"

// warning messages
#define MCPARAMS   "101"
#define MCMSG      "102"
#define MCCMD      "103"
#define MCUSERINV  "104"
#define MCUNIMPL   "105"
#define MCUSERUNK  "106"
#define MCNOSELF   "107"
#define MCNODUPES  "108"

// rate limit messages

// permissions messages
#define MCNEEDUSER "201"
#define MCNEEDPASS "202"
#define MCLOGIN    "203"

// authentication messages
#define MCUSER     "301"
#define MCPASS     "302"
#define MCRESET    "303"

		{ MCSERVER  , "tchatd-" VERSION             },
		{ MCMOTD    , "message of the day"          },
		{ MCNAME    , "server name"                 },
		{ MCCREATED , "login created"               },
		{ MCVERIFIED, "login verified"              },

		{ MCFRIEND  , "friend"                      },
		{ MCREQUEST , "request"                     },
		{ MCANTI    , "anti"                        },
		{ MCDISTANCE, "distance"                    },
		{ MCRREQUEST, "request from"                },
		{ MCRANTI   , "anti from"                   },

		{ MCBEGIN   , "begin"                       },
		{ MCEND     , "end"                         },

		{ MCNEWUSER , "changed username"            },
		{ MCNEWPASS , "changed password"            },

		{ MCGOODBYE , "goodbye"                     },

		{ MCUNIMPL  , "command unimplemented"       },

		{ MCNEEDUSER, "please provide username"     },
		{ MCNEEDPASS, "please provide password"     },
		{ MCLOGIN   , "command requires login"      },

		{ MCPARAMS  , "incorrect parameters"        },
		{ MCMSG     , "missing message"             },
		{ MCCMD     , "unknown command"             },
		{ MCUSERINV , "username invalid"            },
		{ MCUSERUNK , "unknown user"                },
		{ MCNOSELF  , "cannot target self"          },

		{ MCUSER    , "username unavailable"        },
		{ MCPASS    , "incorrect password"          },
		{ MCRESET   , "start login over"            },
		{ MCNODUPES , "multiple logins not allowed" },

		{ NULL      , NULL                          }
	};

	msgmap_t messages;
}

struct partial_login {
	string username;
	string password;
};

namespace state {

	int sd = -1;

	fd_set rfds;
	fd_set wfds;

	fdset_t fdset;

	map<int,stringstream *,int_compar> recvstreams;

	unsigned int next_user_id = 1;

	userlist_t users;

	map<unsigned int,user *,uint_compar> users_by_id;
	map<unsigned int,user *,uint_compar> users_by_fd;
	map<const char *,user *,str_compar> users_by_username;
	map<unsigned int,unsigned int,uint_compar> fd_by_id;

	map<unsigned int,struct partial_login,uint_compar> partial_logins;
}

namespace status {

	bool done = false;
}

namespace option {

	bool verbose = false;
	bool debug = false;
}

namespace config {

#define MAXUSERSZ 24
#define DFLUSERSZ 16
#define MAXCMDSZ  512
#define DFLPORT   30201

	unsigned int port = DFLPORT;
	unsigned int connections = FD_SETSIZE;
	unsigned int backlog = SOMAXCONN;
	unsigned int maxcmdsz = MAXCMDSZ;
	unsigned int maxusersz = DFLUSERSZ;
	struct in_addr ip = { INADDR_ANY };

	string servername("our tchatd server");
	string motd("welcome to our tchat server");
}


int randomrange(int a, int b) {
	double d = (b - a + 1) * (double)random() / (RAND_MAX + 1.0);
	int c = (int)floor(d);
	return c + a;
}

struct node {
	unsigned int id;
	unsigned int distance;
};

typedef list<node> nodelist_t;

class route : public map<unsigned int,set<unsigned int>,uint_compar> {
	public:
	private:
};

class user {
	public:
		unsigned int id;

		string username;
		string pwhash;
		string salt;

		bool visible;

		double action_rate;
		struct timeval last_action;

		friendset_t friends;
		friendset_t friend_requests;
		
		route ospf;
		nodelist_t nodes;

		user() : id(state::next_user_id++), visible(true) {

			state::users.push_back(this);
			state::users_by_id[id] = this;
		}

		user(const string& new_username) : id(state::next_user_id++), visible(true) {

			state::users.push_back(this);
			state::users_by_id[id] = this;

			set_username(new_username);
		}

		user(const string& new_username, const string& new_password) : id(state::next_user_id++), visible(true) {

			state::users.push_back(this);
			state::users_by_id[id] = this;

			set_username(new_username);
			set_password(new_password);
		}

		bool set_username(const string& new_username) {

			// remove old username

			DEBUG_MESSAGE;

			if(!username.empty()) {
				DEBUG_MESSAGE2("removing old username");
				state::users_by_username.erase(username.c_str());
			}

			// add new username

			username = new_username;

			state::users_by_username[new_username.c_str()] = this;

			return true;
		}
		
		bool check_password(const string &try_password) {

			DEBUG_MESSAGE;

			string try_pwhash(crypt(try_password.c_str(), salt.c_str()));

			return (try_pwhash == pwhash);
		}

		bool set_password(const string& new_password) {

			DEBUG_MESSAGE;

			salt = "$1$";

			salt += randomrange('a', 'z');
			salt += randomrange('a', 'z');
			salt += randomrange('a', 'z');
			salt += randomrange('a', 'z');

			salt += '$';

			pwhash = crypt(new_password.c_str(), salt.c_str());

			return true;
		}

	private:
};

int main(int argc, char **argv) {

	// register save, cleanup and signal handling

	signal(SIGINT, sighandler);
	signal(SIGHUP, sighandler);
	signal(SIGALRM, sighandler);
	signal(SIGUSR1, sighandler);
	signal(SIGUSR2, sighandler);

	atexit(do_cleanup);
	atexit(do_save);

	// check options

	do_options(argc, argv);

	// load configuration

	do_config();

	// load state

	do_load();

	// start main event loop

	do_work();

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
	printf("\t%-*s%s\n\n", width, "-h", "help");
}

void do_options(int argc, char **argv) {

	int opt;

	DEBUG_MESSAGE;

	while ((opt = getopt(argc, argv, "vVDhP:T:A:B:c:n:M:S:")) != -1) {

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

				option::verbose = true;
				break;

			case 'V':

				version();
				exit(EXIT_SUCCESS);

			case 'D':

				option::debug = true;
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
		option::debug && puts("interrupt caught");
		exit(EXIT_SUCCESS);
	} else if(signo == SIGHUP) {
		option::debug && puts("hang-up caught");
		exit(EXIT_SUCCESS);
	} else if(signo == SIGALRM) {
		option::debug && puts("alarm caught");
	} else if(signo == SIGUSR1) {
		option::debug && puts("user signal 1 caught");
	} else if(signo == SIGUSR2) {
		option::debug && puts("user signal 2 caught");
	}
}

void handle_error(const char *str) {
	perror(str);
	exit(EXIT_FAILURE);
}

void do_config() {

	const int width = 20;

	char str[80];

	DEBUG_MESSAGE;

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

	if(option::verbose) {
		printf("%*s | %s:%d\n", width, "will bind to", config::ip.s_addr == INADDR_ANY ? "any" : inet_ntop(AF_INET, &config::ip, str, sizeof(str)), config::port);
		printf("%*s | %d\n", width, "maximum connections", config::connections);
		printf("%*s | %d\n", width, "connection backlog", config::backlog);
		printf("%*s | %d bytes\n", width, "maximum command size", config::maxcmdsz);
		printf("%*s | %d bytes\n", width, "maximum username length", config::maxusersz);
		printf("%*s | %s\n", width, "server name", config::servername.c_str());
		printf("%*s | %s\n", width, "message of the day", config::motd.c_str());
	}
}

void do_load_users() {
	DEBUG_MESSAGE;
	// FIXME: load users
}

void do_load_friends() {
	DEBUG_MESSAGE;
	// FIXME: load friends
}

void do_load_routes() { 
	DEBUG_MESSAGE;
	// FIXME: load routes
}

void do_load_sockets() {

	struct sockaddr_in sin;

	DEBUG_MESSAGE;

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

void do_load_command() {
	
	DEBUG_MESSAGE;

	for(unsigned int i = 0; command::command_pairs[i].command_name != NULL; i++)
		command::calls[command::command_pairs[i].command_name] = command::command_pairs[i].command_fptr;

	for(unsigned int i = 0; command::msg_pairs[i].msg_code != NULL; i++)
		command::messages[command::msg_pairs[i].msg_code] = command::msg_pairs[i].msg_str;
}

void do_load() {

	DEBUG_MESSAGE;

	do_load_users();
	do_load_friends();
	do_load_routes();

	do_load_sockets();

	do_load_command();

	// connect to listening interface (socket/bind/listen)
}

void do_work() {

	DEBUG_MESSAGE;

	while(!status::done) {

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

				option::debug && puts("no data");
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

	struct sockaddr_in sin;

	DEBUG_MESSAGE;

	socklen_t sl = sizeof(sin);

	int fd = accept(state::sd, (struct sockaddr *)&sin, &sl);
	if(fd == -1)
		handle_error("accept");

	state::fdset.insert(fd);
	state::recvstreams[fd] = new stringstream(stringstream::binary|stringstream::out|stringstream::in);

	do_message(fd, MCSERVER, PROGRAM " " VERSION);
}

void do_disconnect(int fd) {

	option::debug && printf("disconnecting %d\n", fd);

	if(state::users_by_fd.find(fd) != state::users_by_fd.end()) {
		unsigned int user_id = state::users_by_fd[fd]->id;
		state::fd_by_id.erase(user_id);
	}

	state::fdset.erase(fd);

	delete state::recvstreams[fd];
	state::recvstreams.erase(fd);
	state::users_by_fd.erase(fd);
	state::partial_logins.erase(fd);

	while(close(fd) == -1 && errno == EINTR) {
		// do nothing
	}
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

	option::debug && printf("reading up to %ld bytes from %d\n", (long)sizeof(buf), fd);

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

			option::debug && printf("read %d bytes from %d\n", n, fd);

			state::recvstreams[fd]->write(buf, n);

			do_handle_input(fd);
	}
}

void do_send(int fd, const void *buf, size_t len, int flags) {

	size_t left = len;
	size_t done = 0;

	do {
		int n = send(fd, buf, left, flags);
		if(n == -1) {
			if(errno == EINTR)
				continue;
			else
				handle_error("send");
		} else {
			left -= n;
			done += n;
		}
	} while(left > 0);
}

void do_message(int fd, const char *msg_code, const char *msg) {

	DEBUG_MESSAGE;

	char line[config::maxcmdsz];

	const char *msg_str;

	// make sure msg_code has a msg_str otherwise let the msg_str be "unknown code"

	if(command::messages.find(msg_code) == command::messages.end())
		msg_str = "unknown code";
	else
		msg_str = command::messages[msg_code];

	// decide if the code has a custom message or not

	if(msg == NULL)
		snprintf(line, config::maxcmdsz, "%s %s\n", msg_code, msg_str);
	else
		snprintf(line, config::maxcmdsz, "%s %s :%s\n", msg_code, msg_str, msg);

	do_send(fd, line, strlen(line), 0);
}

void do_message(int fd, const char *msg_code, const string& msg_string) {
	do_message(fd, msg_code, msg_string.c_str());
}

void do_message(int fd, const char *msg_code) {
	do_message(fd, msg_code, NULL);
}

void do_relay(int fd, const string& username, const char *command, unsigned int distance, const paramlist_t& params, const string& msg) {
	DEBUG_MESSAGE;

	char line[config::maxcmdsz];
	string params_string("");

	// join all the params together
	for(paramlist_t::const_iterator p_itr = params.begin(); p_itr != params.end(); /* inc in body */) {
		params_string += *p_itr;
		if(++p_itr != params.end())
			params_string += ' ';
	}

	// add msg if there is non-empty one

	if(msg.empty()) {
		snprintf(line, config::maxcmdsz, "%s %s %d %s\n", username.c_str(), command, distance, params_string.c_str());
	} else {
		snprintf(line, config::maxcmdsz, "%s %s %d %s :%s\n", username.c_str(), command, distance, params_string.c_str(), msg.c_str());
	}

	do_send(fd, line, strlen(line), 0);
}

bool is_valid_username(const string& username) {
	DEBUG_MESSAGE;
	if(username.length() > 0 && username.length() <= config::maxusersz) {
		for(unsigned int i = 0; i < username.length(); i++)
			if(!isalnum(username[i]))
				return false;
		return true;
	}
	return false;
}

bool is_validated(int fd) {
	DEBUG_MESSAGE;
	return (state::users_by_fd.find(fd) != state::users_by_fd.end());
}

bool is_valid_partial_login(int fd, const char *username, const char *password) {

	DEBUG_MESSAGE;

	struct partial_login& pl = state::partial_logins[fd];

	if(username != NULL) {
		if(is_valid_username(username))
			pl.username = username;
		else
			return false;
	}

	if(password != NULL)
		pl.password = password;

	if(!pl.username.empty() && !pl.password.empty()) {

		// theres enough login information to attempt a login or create a new user
		// so do either of those, and if the login attempt fails for a known user
		// then fail the partial login and reset the partial login entry.

		DEBUG_MESSAGE2("doing complete login check");

		if(state::users_by_username.find(pl.username.c_str()) == state::users_by_username.end()) {

			// create new user since we dont know this user
			// user constructor knows how to save itself to the relevant places

			DEBUG_MESSAGE2("doing new user creation");

			user *new_user = state::users_by_fd[fd] = new user(pl.username, pl.password);

			state::fd_by_id[new_user->id] = fd;

			do_message(fd, MCCREATED, new_user->username);

			if(option::debug) {
				printf("created user username=%s salt=%s pwhash=%s\n", new_user->username.c_str(), new_user->salt.c_str(), new_user->pwhash.c_str());
			}

			return true;

		} else {

			// load the user up and check the password

			DEBUG_MESSAGE2("doing known user login");

			user *known_user = state::users_by_username[pl.username.c_str()];

			if(known_user->check_password(pl.password)) {

				// login was good so validate by putting into fd->user map
				// unless the user is already in the map, which in that case
				// error no double logins

				if(state::fd_by_id.find(known_user->id) == state::fd_by_id.end()) {

					state::users_by_fd[fd] = known_user;

					state::fd_by_id[known_user->id] = fd;

					state::partial_logins.erase(fd);

					return true;

				} else {

					do_message(fd, MCNODUPES, known_user->username);

					state::partial_logins.erase(fd);
					do_message(fd, MCRESET);
					
					return false;
				}

			} else {
				
				// login was bad so reset the partial login state

				state::partial_logins.erase(fd);
				do_message(fd, MCRESET);

				return false;
			}
		}
	}

	// partial login, return true but no state adjustments

	return true;
}

void do_login(int fd) {
	do_message(fd, MCVERIFIED, state::users_by_fd[fd]->username);
	do_message(fd, MCMOTD, config::motd);
	do_message(fd, MCNAME, config::servername);
}

void do_command_user(int fd, const paramlist_t& params, const string& msg) {
	option::debug && printf("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if((long)params.size() == 0) {

		do_message(fd, MCPARAMS, CUSER);

	} else if(is_validated(fd)) {

		// do a username change

		user *user = state::users_by_fd[fd];
		const string& username = *params.begin();

		if(is_valid_username(username)) {

			if(state::users_by_username.find(username.c_str()) == state::users_by_username.end()) {

				// set username since its valid

				user->set_username(username);
				do_message(fd, MCNEWUSER, username.c_str());

			} else {

				do_message(fd, MCUSER);
			}

		} else {

			// otherwise say its invalid
			do_message(fd, MCUSERINV);
		}

	} else if(is_valid_partial_login(fd, params.begin()->c_str(), NULL)) {

		// do a login or new user creation

		if(is_validated(fd)) {

			// do login
			do_login(fd);

		} else {

			// prompt for password
			do_message(fd, MCNEEDPASS);
		}

	} else {

		do_message(fd, MCUSER);
		// dis-allow user change
	}
}
void do_command_pass(int fd, const paramlist_t& params, const string& msg) {
	option::debug && printf("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if((long)params.size() == 0) {

		do_message(fd, MCPARAMS, CPASS);

	} else if(is_validated(fd)) {

		// do pass change

		user *user = state::users_by_fd[fd];
		const string& password = *params.begin();

		user->set_password(password);

		do_message(fd, MCNEWPASS);

	} else if(is_valid_partial_login(fd, NULL, params.begin()->c_str())) {

		if(is_validated(fd)) {

			// do login
			do_login(fd);

		} else {

			// prompt for user
			do_message(fd, MCNEEDUSER);
		}

	} else {

		// FIXME: add if too many attempts, ban
		// otherwise wrong password retard

		do_message(fd, MCPASS);
	}
}
void do_command_set(int fd, const paramlist_t& params, const string& msg) {
	option::debug && printf("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());
	if(is_validated(fd)) {
		do_message(fd, MCUNIMPL, CSET);
		// if VAR ok
			// if is unset
				// unset VAR
			// else 
				// set VAR
	} else {
		do_message(fd, MCLOGIN, CSET);
	}
}
void do_send_ping(int from, int to, int distance, const paramlist_t& params, const string& msg) {
	// FIXME: implement SEND PING
	do_message(from, MCUNIMPL, CPING);
}
bool is_online(unsigned int user_id) {
	return (state::fd_by_id.find(user_id) != state::fd_by_id.end());
}
void do_command_ping(int fd, const paramlist_t& params, const string& msg) {
	option::debug && printf("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());
	if(is_validated(fd)) {

		// FIXME: add params checks for PING

		if(params.size() != 0) { 
			do_message(fd, MCPARAMS, CPING);
		} else {

			user *user = state::users_by_fd[fd];

			for(nodelist_t::iterator ritr = user->nodes.begin(); ritr != user->nodes.end(); ritr++) {
				// TODO: possibly check distance
				// also, check if target is online
				if(is_online(ritr->id))
					do_send_ping(fd, state::fd_by_id[ritr->id], ritr->distance, params, msg);
			}
		}

	} else {
		do_message(fd, MCLOGIN, CPING);
	}
}
void do_send_pong(int from, int to, int distance, const paramlist_t& params, const string& msg) {
	// FIXME: implement SEND PONG
	do_message(from, MCUNIMPL, CPONG);
}
void do_command_pong(int fd, const paramlist_t& params, const string& msg) {
	option::debug && printf("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());
	if(is_validated(fd)) {

		if(params.size() != 0) {
			do_message(fd, MCPARAMS, CPONG);
		} else {

			user *user = state::users_by_fd[fd];

			for(nodelist_t::iterator ritr = user->nodes.begin(); ritr != user->nodes.end(); ritr++) {
				// TODO: possibly check distance
				// also, check if target is online
				if(is_online(ritr->id))
					do_send_pong(fd, ritr->id, ritr->distance, params, msg);
			}
		}

	} else {
		do_message(fd, MCLOGIN, CPONG);
	}
}
void do_command_friend(int fd, const paramlist_t& params, const string& msg) {

	option::debug && printf("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if(is_validated(fd)) {

		if(params.size() != 1) {

			do_message(fd, MCPARAMS, CFRIEND);

		} else if(state::users_by_username.find(params.begin()->c_str()) != state::users_by_username.end()) {

			// if user exists, then check if a friend request exists in the opposite direction
			// then decide if this represents a new friend request or a friend request approval

			user *user1 = state::users_by_fd[fd];
			user *user2 = state::users_by_username[params.begin()->c_str()];

			if(user1->id == user2->id) {
				do_message(fd, MCNOSELF, CFRIEND);
			} else {

				if(user2->friend_requests.find(user1->id) != user2->friend_requests.end()) {

					// user is in the friend_request lists of target,
					// so remove friend_request and then add as friends for both users
					// notify users of friend

					user2->friend_requests.erase(user1->id);
					user1->friends.insert(user2->id);
					user2->friends.insert(user1->id);

					do_message(fd, MCFRIEND, user2->username);

					if(is_online(user2->id)) {
						do_message(state::fd_by_id[user2->id], MCRREQUEST, user1->username);
						do_message(state::fd_by_id[user2->id], MCFRIEND, user1->username);
					}

				} else {
					// add as friend request
					// notify users of friend request

					user1->friend_requests.insert(user2->id);

					do_message(fd, MCREQUEST, user2->username);
					if(is_online(user2->id))
						do_message(state::fd_by_id[user2->id], MCRREQUEST, user1->username);
				}
			}
		} else {
			do_message(fd, MCUSERUNK, CFRIEND);
		}
	} else {
		do_message(fd, MCLOGIN, CFRIEND);
	}
}
void do_command_anti(int fd, const paramlist_t& params, const string& msg) {

	option::debug && printf("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if(is_validated(fd)) {

		if(params.size() != 1) {

			do_message(fd, MCPARAMS, CANTI);

		} else if(state::users_by_username.find(params.begin()->c_str()) != state::users_by_username.end()) {

			user *user1 = state::users_by_fd[fd];
			user *user2 = state::users_by_username[params.begin()->c_str()];

			if(user1->id == user2->id) {
				do_message(fd, MCNOSELF, CANTI);
			} else {

				// remove any friends or friend requests and notify users
				
				if(user1->friends.find(user2->id) != user1->friends.end()) {
					user1->friends.erase(user2->id);
				} else if(user1->friend_requests.find(user2->id) != user1->friend_requests.end()) {
					user1->friend_requests.erase(user2->id);
				}

				do_message(fd, MCANTI, user2->username);

				if(user2->friends.find(user1->id) != user2->friends.end()) {
					user2->friends.erase(user1->id);
				} else if(user2->friend_requests.find(user1->id) != user2->friend_requests.end()) {
					user2->friend_requests.erase(user1->id);
				}

				if(is_online(user2->id))
					do_message(state::fd_by_id[user2->id], MCRANTI, user1->username);
			}

		} else {
			do_message(fd, MCUSERUNK, CANTI);
		}

	} else {
		do_message(fd, MCLOGIN, CANTI);
	}
}
void do_command_listen(int fd, const paramlist_t& params, const string& msg) {
	option::debug && printf("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());
	do_message(fd, MCUNIMPL, CLISTEN);
	// listen CLISTEN
}
void do_command_say(int fd, const paramlist_t& params, const string& msg) {
	option::debug && printf("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());
	if(is_validated(fd)) {
		do_message(fd, MCUNIMPL, CSAY);
		// say route CSAY
	} else {
		do_message(fd, MCLOGIN, CSAY);
	}
}
void do_command_vector(int fd, const paramlist_t& params, const string& msg) {
	option::debug && printf("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());
	if(is_validated(fd)) {
		do_message(fd, MCUNIMPL, CVECTOR);
		// vector route CVECTOR
	} else {
		do_message(fd, MCLOGIN, CVECTOR);
	}
}
void do_command_radio(int fd, const paramlist_t& params, const string& msg) {
	option::debug && printf("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());
	do_message(fd, MCUNIMPL, CRADIO);
	// relay CRADIO
}
void do_command_whisper(int fd, const paramlist_t& params, const string& msg) {
	option::debug && printf("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());
	if(is_validated(fd)) {
		do_message(fd, MCUNIMPL, CWHISPER);
		// whisper route CWHISPER
	} else {
		do_message(fd, MCLOGIN, CWHISPER);
	}
}
void do_command_tell(int fd, const paramlist_t& params, const string& msg) {
	option::debug && printf("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());
	if(is_validated(fd)) {
		do_message(fd, MCUNIMPL, CTELL);
		// if user exists
			// relay CTELL
	} else {
		do_message(fd, MCLOGIN, CTELL);
	}
}
void do_command_whois(int fd, const paramlist_t& params, const string& msg) {
	option::debug && printf("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());
	do_message(fd, MCUNIMPL, CWHOIS);
	// if user exists
		// if usr is self
			// do MCWHOIS on self
		// else if user is visible
			// do MCWHOIS on params.being()
}
void do_command_scan(int fd, const paramlist_t& params, const string& msg) {
	option::debug && printf("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());
	if(is_validated(fd)) {
		do_message(fd, MCUNIMPL, CSCAN);
		// for each distance
			// for each friend at distance
				// if friend is visible
					// do MCDISTANCE
	} else {
		do_message(fd, MCLOGIN, CSCAN);
	}
}
void do_command_friends(int fd, const paramlist_t& params, const string& msg) {

	option::debug && printf("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if(is_validated(fd)) {

		user *user = state::users_by_fd[fd];

		// do friends

		do_message(fd, MCBEGIN, MCFRIEND);

		for(friendset_t::iterator friend_itr = user->friends.begin(); friend_itr != user->friends.end(); friend_itr++)
			do_message(fd, MCFRIEND, state::users_by_id[*friend_itr]->username);

		do_message(fd, MCEND, MCFRIEND);

		// do friend requests

		do_message(fd, MCBEGIN, MCREQUEST);

		for(friendset_t::iterator request_itr = user->friend_requests.begin(); request_itr != user->friend_requests.end(); request_itr++)
			do_message(fd, MCREQUEST, state::users_by_id[*request_itr]->username);

		do_message(fd, MCEND, MCREQUEST);

		// do reverse requests

		do_message(fd, MCBEGIN, MCRREQUEST);

		for(userlist_t::iterator user_itr = state::users.begin(); user_itr != state::users.end(); user_itr++)
			for(friendset_t::iterator request_itr = (*user_itr)->friend_requests.begin(); request_itr != (*user_itr)->friend_requests.end(); request_itr++)
				if(*request_itr == user->id)
					do_message(fd, MCRREQUEST, (*user_itr)->username);

		do_message(fd, MCEND, MCRREQUEST);

	} else {
		do_message(fd, MCLOGIN, CFRIENDS);
	}
}
void do_command_quit(int fd, const paramlist_t& params, const string& msg) {
	option::debug && printf("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());
	do_message(fd, MCGOODBYE);
	do_disconnect(fd);
}

void do_unknown_command(int fd, const string& command, const paramlist_t& params, const string& msg) {
	option::debug && printf("*** %s ( %d %s [ %ld ] %s )\n", __FUNCTION__, fd, command.c_str(), (long)params.size(), msg.c_str());
	do_message(fd, MCCMD, command.c_str());
}

void do_handle_line(int fd, const char *line) {

	stringstream ss(line, stringstream::in | stringstream::out);

	string command;
	list<string> params;
	string msg;

	option::debug && printf("processing line for %d : %s\n", fd, line);

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

	if(command_itr == command::calls.end())
		do_unknown_command(fd,command,params,msg);
	else
		(command_itr->second)(fd,params,msg);
}

void do_handle_input(int fd) {

	char line[config::maxcmdsz];
	stringstream *ss = state::recvstreams[fd];
	stringbuf sb;

	DEBUG_MESSAGE;

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

				option::debug && puts("command too long");
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
		option::debug && puts("not enough data");
	}
}

void do_save_users() {
	DEBUG_MESSAGE;
}

void do_save_friends() {
	DEBUG_MESSAGE;
}

void do_save_routes() {
	DEBUG_MESSAGE;
}

void do_save() {

	DEBUG_MESSAGE;

	do_save_users();
	do_save_friends();
	do_save_routes();
}

void do_cleanup_sockets() {

	DEBUG_MESSAGE;

	if(state::sd >= 0)
		close(state::sd);

	fdset_t::iterator fd_itr = state::fdset.begin();

	while(fd_itr != state::fdset.end()) {
		int fd = *fd_itr++; // kinda weird, but the iterator is unhappy when the item gets removed
		do_disconnect(fd);
	}
}

void do_cleanup_temp() {
	DEBUG_MESSAGE;
}

void do_cleanup() {
	DEBUG_MESSAGE;
	do_cleanup_sockets();
	do_cleanup_temp();
}
