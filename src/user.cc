#include <stdexcept>

#include "meshchatd.hh"
#include "network.hh"
#include "user.hh"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <ctype.h>

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

	set_username(new_username);
	set_password(new_password);

	state::users.push_back(this);
	state::users_by_id[id] = this;
}

#include <iostream>

bool user::set_username(const string& new_username) {

	DEBUG_MESSAGE;

	// if new username exists throw exception

	if(new_username == username)
		return true;

	if(user::exists(new_username))
		throw runtime_error("username already exists");

	// remove old username

	if(!username.empty()) {
		DEBUG_MESSAGE2("removing old username");
		state::users_by_username.erase(username.c_str());
	}

	// add new username

	username = new_username;

	state::users_by_username[username.c_str()] = this;

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
	return friends.has(id);
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

	if(visited.missing(current.id)) {

		// mark this node as visited

		visited.insert(current.id);

		// save it as a node if its close enough

		if(current.distance > 0 && current.distance <= config::maxdistance)
			nodes.push_back(current);

		// push all the unvisited neighbors
		// onto the back of the todo list
		// with an adjusted distance
		// so long as they are within the neighborhood
		// (note that this last constraint is an optimization
		// that works for the BFS or OSPF algorithms but not
		// any general spanning tree algorithm)

		user *user = state::users_by_id[current.id];

		for(friendset_t::iterator fitr = user->friends.begin(); fitr != user->friends.end(); fitr++)
			if(visited.missing(*fitr))
				if(current.distance + 1 <= config::maxdistance)
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

friendset_t user::getnumbers(stringstream& ss) {

	friendset_t fs;

	while(true) {

		unsigned int fid;

		ss >> fid;

		if(ss.fail())
			break;

		fs.insert(fid);
	}

	ss.clear();

	return fs;
}

user::user(const string& serialized) {

	string magic;
	string new_username;

	stringstream ss(stringstream::binary|stringstream::out|stringstream::in);

	ss << dec << boolalpha << skipws;

	ss << serialized;

	ss >> magic >> id >> new_username >> pwhash >> salt >> actions >> visible >> last_action_at >> created_at;

	if(magic != "u")
		throw runtime_error("user deserialization failed at user properties");

	ss >> magic;

	if(magic != "f")
		throw runtime_error("user deserialization failed at friends");

	friends = getnumbers(ss);

	ss >> magic;

	if(magic != "r")
		throw runtime_error("user deserialization failed at friend requests");

	friend_requests = getnumbers(ss);

	if(id >= state::next_user_id)
		state::next_user_id = id + 1;

	set_username(new_username);

	state::users.push_back(this);
	state::users_by_id[id] = this;
}

string user::serialize() {

	// format is u ID USERNAME PWHASH SALT ACTIONS VISIBLE LAST_ACTION_AT CREATED_AT f FRIEND... r FRIEND...

	stringstream ss(stringstream::binary|stringstream::out|stringstream::in);

	// stream config

	ss << dec << boolalpha;

	// user data

	ss << "u " << id << ' ' << username << ' ' << pwhash << ' ' << salt << ' ';
	ss << actions << ' ' << visible << ' ';
	ss << last_action_at << ' ' << created_at << ' ';

	// friends

	ss << "f ";
	for(friendset_t::iterator fitr = friends.begin(); fitr != friends.end(); fitr++)
		ss << *fitr << ' ';

	// friend requests

	ss << "r ";
	for(friendset_t::iterator fitr = friend_requests.begin(); fitr != friend_requests.end(); fitr++)
		ss << *fitr << ' ';

	//terminator (newline)

	ss << endl;

	return ss.str();
}

bool user::exists(const string& my_username) {
	return user::exists(my_username.c_str());
}

bool user::exists(const char *my_username) {
	return state::users_by_username.has(my_username);
}
