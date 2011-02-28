#include "tchatd.hh"

namespace config {

	bool verbose = false;
	bool debug = false;
	bool test = false;

	unsigned int port = DFLPORT;
	unsigned int connections = FD_SETSIZE;
	unsigned int backlog = SOMAXCONN;
	unsigned int maxcmdsz = MAXCMDSZ;
	unsigned int maxusersz = DFLUSERSZ;

	std::string servername("our tchatd server");
	std::string motd("welcome to our tchat server");
	struct in_addr ip = { INADDR_ANY };
}
