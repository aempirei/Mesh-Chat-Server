#ifndef MESHCHATD_STATE_HH
#define MESHCHATD_STATE_HH

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

	extern MAP<int,std::stringstream *> recvstreams;

	extern unsigned int next_user_id;

	extern userlist_t users;

	extern MAP<unsigned int,user *> users_by_id;
	extern MAP<unsigned int,user *> users_by_fd;
	extern MAP<const char *,user *,str_compar> users_by_username;
	extern MAP<unsigned int,int> fd_by_id;

	extern MAP<unsigned int,struct partial_login> partial_logins;

	extern bool done;
}

#endif
