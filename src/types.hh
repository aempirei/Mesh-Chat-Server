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

template<typename _Key, typename _Compare = std::less<_Key>, typename _Alloc = std::allocator<_Key> >
class SET : public std::set<_Key,_Compare,_Alloc> {
	public:
		bool has(const _Key& value) {
			return this->find(value) != this->end();
		}
		bool missing(const _Key& value) {
			return ! has(value);
		}
};

template<typename _Key, typename _Tp, typename _Compare = std::less<_Key>, typename _Alloc = std::allocator<std::pair<const _Key, _Tp> > >
class MAP : public std::map<_Key,_Tp,_Compare,_Alloc> {
	public:

		bool has(const _Key& value) {
			return this->find(value) != this->end();
		}
		bool missing(const _Key& value) {
			return ! has(value);
		}
};

typedef SET<int> fdset_t;
typedef SET<unsigned int> friendset_t;

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

typedef std::list<std::string> paramlist_t;
typedef std::list<user *> userlist_t;
typedef std::list<node> nodelist_t;

#endif
