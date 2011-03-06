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

	// configpath gets prepended by $HOME during sub_config()

	std::string configpath(DFLCONFIGPATH);
	std::string savefile(DFLSAVEFILE);
	std::string servername(DFLSERVERNAME);
	std::string motd(DFLMOTD);

	struct in_addr ip = { INADDR_ANY };
}
