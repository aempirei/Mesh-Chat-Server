#include "tchatd.hh"
#include "state.hh"

namespace state {

	int sd = -1;

	fd_set rfds;
	fd_set wfds;

	fdset_t fdset;

	std::map<int,std::stringstream *> recvstreams;

	unsigned int next_user_id = 1;

	userlist_t users;

	std::map<unsigned int,user *> users_by_id;
	std::map<unsigned int,user *> users_by_fd;
	std::map<const char *,user *> users_by_username;
	std::map<unsigned int,int> fd_by_id;

	std::map<unsigned int,struct ::partial_login> partial_logins;

	bool done = false;
}
