#ifndef TCHATD_TYPES_HH
#define TCHATD_TYPES_HH

#include <list>
#include <set>
#include <string>

struct strcase_compar {
	bool operator()(const char * str1, const char *str2);
};

struct str_compar {
	bool operator()(const char * str1, const char *str2);
};

typedef std::list<std::string> paramlist_t;

typedef std::set<int> fdset_t;
typedef std::set<unsigned int> friendset_t;

typedef std::pair<unsigned int, unsigned int> edge_t;

class user;

class node {

	public:

		unsigned int id;
		unsigned int distance;

		explicit node(unsigned int id, unsigned int distance);
		user *get_user();
		int get_fd();
};

typedef std::list<user *> userlist_t;
typedef std::list<node> nodelist_t;

#endif
