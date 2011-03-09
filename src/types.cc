#include <string.h>

#include "meshchatd.hh"

bool strcase_compar::operator()(const char * str1, const char *str2) {
	return strcasecmp(str1, str2) < 0;
}

bool str_compar::operator()(const char * str1, const char *str2) {
	return strcmp(str1, str2) < 0;
}

node::node(unsigned int id, unsigned int distance) : id(id), distance(distance) {
}

user *node::get_user() {
	return state::users_by_id[id];
}

int node::get_fd() {
	return state::fd_by_id[id];
}
