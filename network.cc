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

