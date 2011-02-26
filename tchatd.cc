#include <vector>
#include <list>
#include <map>
#include <set>
#include <string>
#include <iostream>
#include <sstream>
#include <stdexcept>

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
#include <stdarg.h>

#define PROGRAM "Topology Chat Server"
#define VERSION "1.0"
#define DEBUG_MESSAGE     DEBUG_MESSAGE2(__FUNCTION__)
#define DEBUG_MESSAGE2(a) option::debug && puts(a)
#define DEBUG_PRINTF      option::debug && printf

using namespace std;

void do_options(int argc, char **argv);
void do_config();
void do_load_users();
void do_load_friends();
void do_load_routes();
void do_load_sockets();
void do_send(int fd, const void *buf, size_t len, int flags);
void do_vmessage(int fd, const char *msg_code, const char *fmt, ...);
void do_message(int fd, const char *msg_code, const string& msg_string);
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

void do_test();

bool is_online(unsigned int user_id);

void handle_error(const char *str);

void sighandler(int);

struct strcase_compar {
	bool operator()(const char * str1, const char *str2) {
		return strcasecmp(str1, str2) < 0;
	}
};

class user;

typedef set<int> fdset_t;
typedef list<user *> userlist_t;
typedef list<string> paramlist_t;
typedef set<unsigned int> friendset_t;
typedef pair<unsigned int, unsigned int> edge_t;

typedef void command_fn_t(int fd, const paramlist_t& params, const string& msg);
typedef map<const char *, command_fn_t *, strcase_compar> commandmap_t;
typedef map<const char *,const char *, strcase_compar> msgmap_t;

command_fn_t do_command_anti;
command_fn_t do_command_friend;
command_fn_t do_command_friends;
command_fn_t do_command_user;
command_fn_t do_command_pass;
command_fn_t do_command_ping;
command_fn_t do_command_pong;
command_fn_t do_command_quit;
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
#define CSAY     "say"
#define CVECTOR  "vector"
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
		{ CSAY    , do_command_say     }, // SAY :message
		{ CVECTOR , do_command_vector  }, // VECTOR username :message
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
#define MCWHOIS    "067"

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
#define MCUSEROFF  "109"

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
		{ MCWHOIS   , "whois"                       },

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
		{ MCUSEROFF , "user offline"                },

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

	map<int,stringstream *> recvstreams;

	unsigned int next_user_id = 1;

	userlist_t users;

	map<unsigned int,user *> users_by_id;
	map<unsigned int,user *> users_by_fd;
	map<const char *,user *> users_by_username;
	map<unsigned int,int> fd_by_id;

	map<unsigned int,struct partial_login> partial_logins;
}

namespace status {

	bool done = false;
}

namespace option {

	bool verbose = false;
	bool debug = false;
	bool test = false;
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

class node {

	public:

		unsigned int id;
		unsigned int distance;

		explicit node(unsigned int id, unsigned int distance) : id(id), distance(distance) {
		}
		user *get_user() {
			return state::users_by_id[id];
		}
		int get_fd() {
			return state::fd_by_id[id];
		}
};

typedef list<node> nodelist_t;

/*

class route : public map<unsigned int,set<unsigned int>,uint_compar> {
	public:
	private:
};

*/

class user {
	private:

		nodelist_t nodes;

	public:
		unsigned int id;

		string username;
		string pwhash;
		string salt;

		unsigned int actions;
		bool visible;

		time_t last_action_at;
		time_t created_at;

		friendset_t friends;
		friendset_t friend_requests;

		bool operator==(const user& ruser) {
			return (id == ruser.id);
		}

		bool operator!=(const user& ruser) {
			return (id != ruser.id);
		}

		bool operator=(const user& user) {
			throw runtime_error("user objects should never be assigned");
		}

		explicit user(const user& user) {
			throw runtime_error("user objects should never be copied");
		}

		// a user object should never be constructed by another constructor,
		// and should never be created via the copy constructor and never
		// get assigned via the assignment operator

		explicit user(const string& new_username, const string& new_password) : id(state::next_user_id++), actions(1), visible(true) {

			last_action_at = created_at = time(NULL);

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

		void tick() {
			actions++;
			last_action_at = time(NULL);
		}

		long idle() {
			return time(NULL) - last_action_at;
		}

		long age() {
			return time(NULL) - created_at;
		}

		double rate() {
			long dt = age();
			return (double)actions / (dt ? dt : 1);
		}

		bool is_online() {
			return ::is_online(id);
		}

		bool has_friend(const user *user) {
			return has_friend(user->id);
		}

		bool has_friend(unsigned int id) {
			return(friends.find(id) != friends.end());
		}

		int get_fd() {
			return is_online() ? state::fd_by_id[id] : -1;
		}

		nodelist_t& get_nodes() {

			nodelist_t todo;
			friendset_t visited;

			todo.push_back(node(id,0));

			nodes.clear();

			span_nodes(todo, visited);

			return nodes;
		}

	private:

		void visit(node& current, nodelist_t& todo, friendset_t& visited) {

			// if this current node is not in the visited set then visit it

			if(visited.find(current.id) == visited.end()) {

				// mark this node as visited

				visited.insert(current.id);

				nodes.push_back(current);

				// push all the unvisited neighbors
				// onto the back of the todo list
				// with an adjusted distance

				user *user = state::users_by_id[current.id];

				for(friendset_t::iterator fitr = user->friends.begin(); fitr != user->friends.end(); fitr++)
					if(visited.find(*fitr) == visited.end())
						todo.push_back(node(*fitr, current.distance + 1));
			}
		}

		void span_nodes(nodelist_t& todo, friendset_t& visited) {

			// while the todo list is not empty
			// process it as first-in first-out

			while(!todo.empty()) {
				visit(todo.front(), todo, visited);
				todo.pop_front();
			}
		}
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

	// test if option is set

	if(option::test)
		do_test();

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
	printf("\t%-*s%s\n", width, "-@", "test mode");
	printf("\t%-*s%s\n\n", width, "-h", "help");
}

void do_options(int argc, char **argv) {

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

				option::verbose = true;
				break;

			case 'V':

				version();
				exit(EXIT_SUCCESS);

			case 'D':

				option::debug = true;
				break;

			case '@':

				option::test = true;
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

void do_disconnect(int fd) {

	DEBUG_PRINTF("disconnecting %d\n", fd);

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

void do_send(int fd, const void *buf, size_t len, int flags) {

    DEBUG_MESSAGE;

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

void do_vmessage(int fd, const char *msg_code, const char *fmt, ...) {

	char msg_str[config::maxcmdsz];
	va_list ap;

	va_start(ap,fmt);
	vsnprintf(msg_str, config::maxcmdsz, fmt, ap);
	va_end(ap);

	do_message(fd, msg_code, msg_str);
}

// fd       -- target fd
// username -- source username
// command  -- issued command
// distance -- distance to target from source
// params   -- any parameters
// msg      -- possible message

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
		snprintf(line, config::maxcmdsz, "@ %s %d %s %s\n", username.c_str(), distance, command, params_string.c_str());
	} else {
		snprintf(line, config::maxcmdsz, "@ %s %d %s %s :%s\n", username.c_str(), distance, command, params_string.c_str(), msg.c_str());
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

bool is_online(unsigned int id) {

	DEBUG_MESSAGE;

	return (state::fd_by_id.find(id) != state::fd_by_id.end());
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

	DEBUG_MESSAGE;

	do_message(fd, MCVERIFIED, state::users_by_fd[fd]->username);
	do_message(fd, MCMOTD, config::motd);
	do_message(fd, MCNAME, config::servername);
}

void do_command_user(int fd, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if((long)params.size() == 0) {

		do_message(fd, MCPARAMS, CUSER);

	} else if(is_validated(fd)) {

		// do a username change

		user *user = state::users_by_fd[fd];
		const string& username = params.front();

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

	} else if(is_valid_partial_login(fd, params.front().c_str(), NULL)) {

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

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if((long)params.size() == 0) {

		do_message(fd, MCPARAMS, CPASS);

	} else if(is_validated(fd)) {

		// do pass change

		user *user = state::users_by_fd[fd];
		const string& password = params.front();

		user->set_password(password);

		do_message(fd, MCNEWPASS);

	} else if(is_valid_partial_login(fd, NULL, params.front().c_str())) {

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

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

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
void do_simple_cmd(const char *cmd, int fd, const paramlist_t& params, const string& msg) {

	if(is_validated(fd)) {

		// no params allowed

		if(params.size() != 0) {
			do_message(fd, MCPARAMS, cmd);
		} else {

			user *user = state::users_by_fd[fd];

			// just walk the tree and relay to online users

			for(nodelist_t::iterator ritr = user->get_nodes().begin(); ritr != user->get_nodes().end(); ritr++)
				if(ritr->get_user()->is_online())
					do_relay(ritr->get_fd(), user->username, cmd, ritr->distance, params, msg);
		}

	} else {
		do_message(fd, MCLOGIN, cmd);
	}
}
void do_command_ping(int fd, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	do_simple_cmd(CPING, fd, params, msg);
}
void do_command_pong(int fd, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	do_simple_cmd(CPONG, fd, params, msg);
}
void do_command_friend(int fd, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if(is_validated(fd)) {

		if(params.size() != 1) {

			do_message(fd, MCPARAMS, CFRIEND);

		} else if(state::users_by_username.find(params.front().c_str()) != state::users_by_username.end()) {

			// if user exists, then check if a friend request exists in the opposite direction
			// then decide if this represents a new friend request or a friend request approval

			user *user1 = state::users_by_fd[fd];
			user *user2 = state::users_by_username[params.front().c_str()];

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

					if(user2->is_online()) {
						do_message(state::fd_by_id[user2->id], MCRREQUEST, user1->username);
						do_message(state::fd_by_id[user2->id], MCFRIEND, user1->username);
					}

				} else {
					// add as friend request
					// notify users of friend request

					user1->friend_requests.insert(user2->id);

					do_message(fd, MCREQUEST, user2->username);
					if(user2->is_online())
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

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if(is_validated(fd)) {

		if(params.size() != 1) {

			do_message(fd, MCPARAMS, CANTI);

		} else if(state::users_by_username.find(params.front().c_str()) != state::users_by_username.end()) {

			user *user1 = state::users_by_fd[fd];
			user *user2 = state::users_by_username[params.front().c_str()];

			if(user1->id == user2->id) {
				do_message(fd, MCNOSELF, CANTI);
			} else {

				// remove any friends or friend requests and notify users

				user1->friends.erase(user2->id);
				user1->friend_requests.erase(user2->id);

				do_message(fd, MCANTI, user2->username);

				user2->friends.erase(user1->id);
				user2->friend_requests.erase(user1->id);

				if(user2->is_online())
					do_message(state::fd_by_id[user2->id], MCRANTI, user1->username);
			}

		} else {
			do_message(fd, MCUSERUNK, CANTI);
		}

	} else {
		do_message(fd, MCLOGIN, CANTI);
	}
}
void do_command_say(int fd, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	do_simple_cmd(CSAY, fd, params, msg);
}
void do_command_vector(int fd, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if(is_validated(fd)) {
		do_message(fd, MCUNIMPL, CVECTOR);
		// vector route CVECTOR
	} else {
		do_message(fd, MCLOGIN, CVECTOR);
	}
}
void do_command_whisper(int fd, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if(is_validated(fd)) {
		do_message(fd, MCUNIMPL, CWHISPER);
		// whisper route CWHISPER
	} else {
		do_message(fd, MCLOGIN, CWHISPER);
	}
}
void do_command_tell(int fd, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if(is_validated(fd)) {

		// TELL username :message

		if(params.size() != 1) {

			do_message(fd, MCPARAMS, CTELL);

		} else if(state::users_by_username.find(params.front().c_str()) != state::users_by_username.end()) {

			user *user1 = state::users_by_fd[fd];
			user *user2 = state::users_by_username[params.front().c_str()];

			if(user2->is_online()) {

				// if user is online then go ahead and relay the CTELL and set the distance to 1
				do_relay(state::fd_by_id[user2->id], user1->username, CTELL, 1, params, msg);

			} else {
				do_message(fd, MCUSEROFF, CTELL);
			}

		} else {
			do_message(fd, MCUSERUNK, CTELL);
		}

	} else {
		do_message(fd, MCLOGIN, CTELL);
	}
}
void do_command_whois(int fd, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if(is_validated(fd)) {

		user *user1 = state::users_by_fd[fd];

		if(params.size() > 1) {

			do_message(fd, MCPARAMS, CWHOIS);

		} else {

			user *user2 = NULL;

			// if theres no parameters then this is a self WHOIS, otherwise its a normal WHOIS, so check if the user exists

			if(params.size() == 0 && is_validated(fd)) {

				user2 = user1;

			} else if(state::users_by_username.find(params.front().c_str()) != state::users_by_username.end()) {

				user2 = state::users_by_username[params.front().c_str()];
			}

			if(user2 == NULL) {

				do_message(fd, MCUSERUNK, CWHOIS);

			} else {

				do_message(fd, MCBEGIN, MCWHOIS);

				do_vmessage(fd, MCWHOIS, "username %s", user2->username.c_str());

				// if the user is invisible then dont show details

				if(user2->visible) {
					do_message(fd, MCWHOIS, "visible true");
					do_vmessage(fd, MCWHOIS, "online %s", user2->is_online() ? "true" : "false");
					do_vmessage(fd, MCWHOIS, "idle %lds", user2->idle());
					do_vmessage(fd, MCWHOIS, "age %lds", user2->age());
				} else {
					do_message(fd, MCWHOIS, "visible false");
				}

				do_message(fd, MCEND, MCWHOIS);

				// let the target user know they got whois'd

				if(user2->is_online())
					do_relay(user2->get_fd(), user1->username, CWHOIS, 1, params, msg);
			}
		}

	} else {
		do_message(fd, MCLOGIN, CWHOIS);
	}
}
void do_command_scan(int fd, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if(params.size() != 0) {
		do_message(fd, MCPARAMS, CSCAN);
	} else if(is_validated(fd)) {

		user *user1 = state::users_by_fd[fd];

		do_message(fd, MCBEGIN, MCDISTANCE);

		for(nodelist_t::iterator ritr = user1->get_nodes().begin(); ritr != user1->get_nodes().end(); ritr++)
			if(ritr->get_user()->visible)
				do_vmessage(fd, MCDISTANCE, "%d %s", ritr->distance, ritr->get_user()->username.c_str());

		do_message(fd, MCEND, MCDISTANCE);

	} else {
		do_message(fd, MCLOGIN, CSCAN);
	}
}
void do_command_friends(int fd, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if(params.size() != 0) {
		do_message(fd, MCPARAMS, CFRIENDS);
	} else if(is_validated(fd)) {

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

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if(params.size() != 0) {
		do_message(fd, MCPARAMS, CQUIT);
	} else {
		do_message(fd, MCGOODBYE);
		do_disconnect(fd);
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
	// FIXME: add save users
}

void do_save_friends() {
	DEBUG_MESSAGE;
	// FIXME: add save friends
}

void do_save_routes() {
	DEBUG_MESSAGE;
	// FIXME: add save routes
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

void do_test() {

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
