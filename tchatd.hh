#ifndef TCHATD_HH
#define TCHATD_HH

#define PROGRAM "Topology Chat Server"
#define VERSION "1.0"
#define DEBUG_MESSAGE     DEBUG_MESSAGE2(__FUNCTION__)
#define DEBUG_MESSAGE2(a) config::debug && puts(a)
#define DEBUG_PRINTF      config::debug && printf

#include <map>
#include <string>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "types.hh"

bool is_online(unsigned int user_id);

void handle_error(const char *str);

int randomrange(int a, int b);

struct partial_login {
	std::string username;
	std::string password;
};

namespace state {

	extern int sd;

	extern fd_set rfds;
	extern fd_set wfds;

	extern fdset_t fdset;

	extern std::map<int,std::stringstream *> recvstreams;

	extern unsigned int next_user_id;

	extern userlist_t users;

	extern std::map<unsigned int,user *> users_by_id;
	extern std::map<unsigned int,user *> users_by_fd;
	extern std::map<const char *,user *> users_by_username;
	extern std::map<unsigned int,int> fd_by_id;

	extern std::map<unsigned int,struct partial_login> partial_logins;

	extern bool done;
}

namespace config {

	extern bool verbose;
	extern bool debug;
	extern bool test;

#define MAXUSERSZ 24
#define DFLUSERSZ 16
#define MAXCMDSZ  512
#define DFLPORT   30201

	extern unsigned int port;
	extern unsigned int connections;
	extern unsigned int backlog;
	extern unsigned int maxcmdsz;
	extern unsigned int maxusersz;

	extern std::string servername;
	extern std::string motd;
	extern struct in_addr ip;
}

#endif
