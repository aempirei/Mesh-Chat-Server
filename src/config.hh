#ifndef TCHATD_CONFIG_HH
#define TCHATD_CONFIG_HH

#include <string>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

namespace config {

	extern bool verbose;
	extern bool debug;
	extern bool test;

#define MAXUSERSZ     24
#define DFLUSERSZ     16
#define MAXCMDSZ      512
#define DFLPORT       30201
#define DFLCONFIGPATH ".tchatd"
#define DFLSAVEFILE   "tchatd.save"
#define DFLSERVERNAME "our tchatd server"
#define DFLMOTD       "welcome to our tchat server"

	extern unsigned int port;
	extern unsigned int connections;
	extern unsigned int backlog;
	extern unsigned int maxcmdsz;
	extern unsigned int maxusersz;

	extern std::string configpath;
	extern std::string savefile;
	extern std::string servername;
	extern std::string motd;

	extern struct in_addr ip;
}

#endif
