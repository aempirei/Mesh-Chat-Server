#include "meshchatd.hh"
#include "user.hh"
#include "network.hh"
#include "commands.hh"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include <math.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
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

	msg_str = command::messages.has(msg_code) ? command::messages[msg_code] : "unknown code";

	// decide if the code has a custom message or not

	snprintf(line, config::maxcmdsz, msg ? "%s %s :%s\n" : "%s %s\n", msg_code, msg_str, msg);

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

	if(state::users_by_fd.has(fd)) {
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
	    	nodelist_t& nl = user->get_nodes();

			// just walk the tree and relay to online users within the neighborhood

			for(nodelist_t::iterator ritr = nl.begin(); ritr != nl.end(); ritr++)
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

		if(state::users_by_username.missing(pl.username.c_str())) {

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

				if(state::fd_by_id.missing(known_user->id)) {

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

	return state::users_by_fd.has(fd);
}

bool is_online(unsigned int id) {

	DEBUG_MESSAGE;

	return state::fd_by_id.has(id);
}

void do_connect() {

	DEBUG_MESSAGE;

	struct sockaddr_in sin;

	socklen_t sl = sizeof(sin);

	int fd = accept(state::sd, (struct sockaddr *)&sin, &sl);
	if(fd == -1)
		handle_error("accept");

	state::fdset.insert(fd);
	state::recvstreams[fd] = new stringstream(stringstream::binary|stringstream::out|stringstream::in);

	do_message(fd, MCSERVER, PROGRAM " " VERSION);
}

void do_read_all() {

	DEBUG_MESSAGE;

	fdset_t::iterator fd_itr = state::fdset.begin();

	while(fd_itr != state::fdset.end()) {
		// process each iterator for reading data, but make sure we get the iterators next position
		// before calling, since do_read() may disconnect an fd which will destroy the associated iterator
		int fd = *fd_itr++;
		if(FD_ISSET(fd, &state::rfds))
			do_read(fd);
	}
}

void do_read(int fd) {

	static char buf[4096];
	int n;

	DEBUG_PRINTF("reading up to %ld bytes from %d\n", (long)sizeof(buf), fd);

	do {
		n = recv(fd, (void *)buf, sizeof(buf), 0);
	} while(n == -1 && errno == EINTR);

	switch(n) {

		case -1:

			perror("recv");
			DEBUG_PRINTF("recv: %s\n", strerror(errno));

		case 0:

			do_disconnect(fd);
			break;

		default:

			DEBUG_PRINTF("read %d bytes from %d\n", n, fd);

			state::recvstreams[fd]->write(buf, n);

			do_handle_input(fd);
	}
}

void do_unknown_command(int fd, const string& command, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("*** %s ( %d %s [ %ld ] %s )\n", __FUNCTION__, fd, command.c_str(), (long)params.size(), msg.c_str());

	do_message(fd, MCCMD, command.c_str());
}

void do_handle_input(int fd) {

	DEBUG_MESSAGE;

	char line[config::maxcmdsz];
	stringstream *ss = state::recvstreams[fd];
	stringbuf sb;

	while(!ss->eof()) {

		// process each line as a command
		// handle incomplete lines and lines that are too long

		ss->getline(line, config::maxcmdsz);

		if(ss->fail()) {

			if(!ss->eof()) {

				// a command was too long if FAIL without EOF so skip it

				ss->clear();
				ss->get(sb, '\n');

				if(ss->peek() == '\n')
					ss->get();

				config::debug && puts("command too long");
			}

		} else if(ss->good()) {

			do_handle_line(fd, line);

			// if connection was closed, then quickly leave since
			// the iterator for ss is no longer valid

			if(state::fdset.missing(fd))
				return;
		}

		// any time we read EOF then theres definitely no more data for now

	}

	ss->clear();

	if(ss->gcount() > 0) {

		// if data was read on the exit round then put it back

		ss->write(line, ss->gcount());
		config::debug && puts("not enough data");
	}
}

void do_handle_line(int fd, const char *line) {

	DEBUG_PRINTF("processing line for %d : %s\n", fd, line);

	stringstream ss(line, stringstream::in | stringstream::out);

	string command;
	list<string> params;
	string msg;

	// a command line is a newline (0x10 '\n') terminated string of the form:
	// COMMAND PARAMS* (:MESSAGE)?

	// get the command

	ss >> skipws >> command >> ws;

	// get zero or more parameters

	while(!ss.eof() && ss.peek() != ':') {
		string next;
		ss >> next >> ws;
		params.push_back(next);
	}

	// get the optional message

	if(!ss.eof() && ss.peek() == ':') {
		stringbuf sb;
		ss.get();
		ss.get(sb);
		msg = sb.str();
	}

	// try to call the corresponding command

	commandmap_t::iterator command_itr = command::calls.find(command.c_str());

	if(command_itr == command::calls.end()) {
		do_unknown_command(fd,command,params,msg);
	} else {
		// if the command is legit, then tick the user if they are validated
		if(is_validated(fd))
			state::users_by_fd[fd]->tick();
		(command_itr->second)(fd,params,msg);
	}
}

