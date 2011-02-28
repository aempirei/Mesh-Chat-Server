#include <sstream>

#include "tchatd.hh"
#include "user.hh"
#include "network.hh"
#include "commands.hh"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include <errno.h>
#include <stdarg.h>

using namespace std;

void do_send(int fd, const void *buf, size_t len, int flags) {

	DEBUG_MESSAGE;

	size_t left = len;
	size_t done = 0;

	do {
		int n = send(fd, buf, left, flags);
		if(n == -1) {
			if(errno == EINTR)
				continue;
			else
				handle_error("send");
		} else {
			left -= n;
			done += n;
		}
	} while(left > 0);
}

void do_message(int fd, const char *msg_code, const char *msg) {

	DEBUG_MESSAGE;

	char line[config::maxcmdsz];

	const char *msg_str;

	// make sure msg_code has a msg_str otherwise let the msg_str be "unknown code"

	if(command::messages.find(msg_code) == command::messages.end())
		msg_str = "unknown code";
	else
		msg_str = command::messages[msg_code];

	// decide if the code has a custom message or not

	if(msg == NULL)
		snprintf(line, config::maxcmdsz, "%s %s\n", msg_code, msg_str);
	else
		snprintf(line, config::maxcmdsz, "%s %s :%s\n", msg_code, msg_str, msg);

	do_send(fd, line, strlen(line), 0);
}

void do_message(int fd, const char *msg_code, const string& msg_string) {
	do_message(fd, msg_code, msg_string.c_str());
}

void do_message(int fd, const char *msg_code) {
	do_message(fd, msg_code, NULL);
}

void do_vmessage(int fd, const char *msg_code, const char *fmt, ...) {

	char msg_str[config::maxcmdsz];
	va_list ap;

	va_start(ap,fmt);
	vsnprintf(msg_str, config::maxcmdsz, fmt, ap);
	va_end(ap);

	do_message(fd, msg_code, msg_str);
}

void do_login(int fd) {

	DEBUG_MESSAGE;

	do_message(fd, MCVERIFIED, state::users_by_fd[fd]->username);
	do_message(fd, MCMOTD, config::motd);
	do_message(fd, MCNAME, config::servername);
}

void do_disconnect(int fd) {

	DEBUG_PRINTF("disconnecting %d\n", fd);

	if(state::users_by_fd.find(fd) != state::users_by_fd.end()) {
		unsigned int user_id = state::users_by_fd[fd]->id;
		state::fd_by_id.erase(user_id);
	}

	state::fdset.erase(fd);

	delete state::recvstreams[fd];
	state::recvstreams.erase(fd);
	state::users_by_fd.erase(fd);
	state::partial_logins.erase(fd);

	while(close(fd) == -1 && errno == EINTR) {
		// do nothing
	}
}

// fd       -- target fd
// username -- source username
// command  -- issued command
// distance -- distance to target from source
// params   -- any parameters
// msg      -- possible message

void do_relay(int fd, const string& username, const char *command, unsigned int distance, const paramlist_t& params, const string& msg) {

	DEBUG_MESSAGE;

	char line[config::maxcmdsz];
	string params_string("");

	// join all the params together
	for(paramlist_t::const_iterator p_itr = params.begin(); p_itr != params.end(); /* inc in body */) {
		params_string += *p_itr;
		if(++p_itr != params.end())
			params_string += ' ';
	}

	// add msg if there is non-empty one

	if(msg.empty()) {
		snprintf(line, config::maxcmdsz, "@ %s %d %s %s\n", username.c_str(), distance, command, params_string.c_str());
	} else {
		snprintf(line, config::maxcmdsz, "@ %s %d %s %s :%s\n", username.c_str(), distance, command, params_string.c_str(), msg.c_str());
	}

	do_send(fd, line, strlen(line), 0);
}

// a simple command is a command that requires neighborhood message relaying and requires no parameters
// cmd    -- command to relay
// fd     -- target fd
// params -- params (which should be empty)
// msg    -- possible message

void do_simple_cmd(const char *cmd, int fd, const paramlist_t& params, const string& msg) {

	if(is_validated(fd)) {

		// no params allowed

		if(params.size() != 0) {
			do_message(fd, MCPARAMS, cmd);
		} else {

			user *user = state::users_by_fd[fd];

			// just walk the tree and relay to online users

			for(nodelist_t::iterator ritr = user->get_nodes().begin(); ritr != user->get_nodes().end(); ritr++)
				if(ritr->get_user()->is_online())
					do_relay(ritr->get_fd(), user->username, cmd, ritr->distance, params, msg);
		}

	} else {
		do_message(fd, MCLOGIN, cmd);
	}
}

bool is_valid_partial_login(int fd, const char *username, const char *password) {

	DEBUG_MESSAGE;

	struct partial_login& pl = state::partial_logins[fd];

	if(username != NULL) {
		if(is_valid_username(username))
			pl.username = username;
		else
			return false;
	}

	if(password != NULL)
		pl.password = password;

	if(!pl.username.empty() && !pl.password.empty()) {

		// theres enough login information to attempt a login or create a new user
		// so do either of those, and if the login attempt fails for a known user
		// then fail the partial login and reset the partial login entry.

		DEBUG_MESSAGE2("doing complete login check");

		if(state::users_by_username.find(pl.username.c_str()) == state::users_by_username.end()) {

			// create new user since we dont know this user
			// user constructor knows how to save itself to the relevant places

			DEBUG_MESSAGE2("doing new user creation");

			user *new_user = state::users_by_fd[fd] = new user(pl.username, pl.password);

			state::fd_by_id[new_user->id] = fd;

			do_message(fd, MCCREATED, new_user->username);

			if(config::debug) {
				printf("created user username=%s salt=%s pwhash=%s\n", new_user->username.c_str(), new_user->salt.c_str(), new_user->pwhash.c_str());
			}

			return true;

		} else {
			// load the user up and check the password

			DEBUG_MESSAGE2("doing known user login");

			user *known_user = state::users_by_username[pl.username.c_str()];

			if(known_user->check_password(pl.password)) {

				// login was good so validate by putting into fd->user map
				// unless the user is already in the map, which in that case
				// error no double logins

				if(state::fd_by_id.find(known_user->id) == state::fd_by_id.end()) {

					state::users_by_fd[fd] = known_user;

					state::fd_by_id[known_user->id] = fd;

					state::partial_logins.erase(fd);

					return true;

				} else {

					do_message(fd, MCNODUPES, known_user->username);

					state::partial_logins.erase(fd);
					do_message(fd, MCRESET);

					return false;
				}

			} else {

				// login was bad so reset the partial login state

				state::partial_logins.erase(fd);
				do_message(fd, MCRESET);

				return false;
			}
		}
	}

	// partial login, return true but no state adjustments
	return true;
}

bool is_valid_username(const string& username) {

	DEBUG_MESSAGE;

	if(username.length() > 0 && username.length() <= config::maxusersz) {
		for(unsigned int i = 0; i < username.length(); i++)
			if(!isalnum(username[i]))
				return false;
		return true;
	}
	return false;
}

bool is_validated(int fd) {

	DEBUG_MESSAGE;

	return (state::users_by_fd.find(fd) != state::users_by_fd.end());
}

bool is_online(unsigned int id) {

	DEBUG_MESSAGE;

	return (state::fd_by_id.find(id) != state::fd_by_id.end());
}

