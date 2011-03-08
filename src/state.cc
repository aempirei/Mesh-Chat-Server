#include "tchatd.hh"
#include "state.hh"

namespace state {

	int sd = -1;

	fd_set rfds;
	fd_set wfds;

	fdset_t fdset;

	MAP<int,std::stringstream *> recvstreams;

	unsigned int next_user_id = 1;

	userlist_t users;

	MAP<unsigned int,user *> users_by_id;
	MAP<unsigned int,user *> users_by_fd;
	MAP<const char *,user *,str_compar> users_by_username;
	MAP<unsigned int,int> fd_by_id;

	MAP<unsigned int,struct ::partial_login> partial_logins;

	bool done = false;
}
