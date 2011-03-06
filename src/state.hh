#ifndef TCHATD_STATE_HH
#define TCHATD_STATE_HH

#include <map>
#include <sstream>

#include "types.hh"

#include <sys/types.h>

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
	extern std::map<const char *,user *,str_compar> users_by_username;
	extern std::map<unsigned int,int> fd_by_id;

	extern std::map<unsigned int,struct partial_login> partial_logins;

	extern bool done;
}

#endif
