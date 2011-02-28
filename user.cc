#include <vector>
#include <list>
#include <map>
#include <set>
#include <string>
#include <iostream>
#include <sstream>
#include <stdexcept>

#include "tchatd.hh"
#include "user.hh"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include <math.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <errno.h>
#include <stdarg.h>

using namespace std;

bool user::operator==(const user& ruser) {
	return (id == ruser.id);
}

bool user::operator!=(const user& ruser) {
	return (id != ruser.id);
}

bool user::operator=(const user& user) {
	throw runtime_error("user objects should never be assigned");
}

user::user(const user& user) {
	throw runtime_error("user objects should never be copied");
}

// a user object should never be constructed by another constructor,
// and should never be created via the copy constructor and never
// get assigned via the assignment operator

user::user(const string& new_username, const string& new_password) : id(state::next_user_id++), actions(1), visible(true) {

	last_action_at = created_at = time(NULL);

	state::users.push_back(this);
	state::users_by_id[id] = this;

	set_username(new_username);
	set_password(new_password);
}

bool user::set_username(const string& new_username) {

	// remove old username

	DEBUG_MESSAGE;

	if(!username.empty()) {
		DEBUG_MESSAGE2("removing old username");
		state::users_by_username.erase(username.c_str());
	}

	// add new username

	username = new_username;

	state::users_by_username[new_username.c_str()] = this;

	return true;
}

bool user::check_password(const string &try_password) {

	DEBUG_MESSAGE;

	string try_pwhash(crypt(try_password.c_str(), salt.c_str()));

	return (try_pwhash == pwhash);
}

bool user::set_password(const string& new_password) {

	DEBUG_MESSAGE;

	salt = "$1$";

	salt += randomrange('a', 'z');
	salt += randomrange('a', 'z');
	salt += randomrange('a', 'z');
	salt += randomrange('a', 'z');

	salt += '$';

	pwhash = crypt(new_password.c_str(), salt.c_str());

	return true;
}

void user::tick() {
	actions++;
	last_action_at = time(NULL);
}

long user::idle() {
	return time(NULL) - last_action_at;
}

long user::age() {
	return time(NULL) - created_at;
}

double user::rate() {
	long dt = age();
	return (double)actions / (dt ? dt : 1);
}

bool user::is_online() {
	return ::is_online(id);
}

bool user::has_friend(const user *user) {
	return has_friend(user->id);
}

bool user::has_friend(unsigned int id) {
	return(friends.find(id) != friends.end());
}

int user::get_fd() {
	return is_online() ? state::fd_by_id[id] : -1;
}

nodelist_t& user::get_nodes() {
	nodes.clear();
	bfs(node(id,0));
	return nodes;
}

void user::visit(node& current, nodelist_t& todo, friendset_t& visited) {

	// if this current node is not in the visited set then visit it

	if(visited.find(current.id) == visited.end()) {

		// mark this node as visited

		visited.insert(current.id);

		nodes.push_back(current);

		// push all the unvisited neighbors
		// onto the back of the todo list
		// with an adjusted distance

		user *user = state::users_by_id[current.id];

		for(friendset_t::iterator fitr = user->friends.begin(); fitr != user->friends.end(); fitr++)
			if(visited.find(*fitr) == visited.end())
				todo.push_back(node(*fitr, current.distance + 1));
	}
}

void user::bfs(const node& root) {

	nodelist_t todo;
	friendset_t visited;

	todo.push_back(root);

	span_nodes(todo, visited);
}

void user::span_nodes(nodelist_t& todo, friendset_t& visited) {

	// while the todo list is not empty
	// process it as first-in first-out

	while(!todo.empty()) {
		visit(todo.front(), todo, visited);
		todo.pop_front();
	}
}
