#include "tchatd.hh"
#include "user.hh"
#include "network.hh"
#include "commands.hh"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

using namespace std;

namespace command {

	struct command_name_fptr_pair command_pairs[] = {

		{ CUSER   , do_command_user    }, // USER username
		{ CPASS   , do_command_pass    }, // PASS password
		{ CSET    , do_command_set     }, // SET property :value
		{ CPING   , do_command_ping    }, // PING :challenge
		{ CPONG   , do_command_pong    }, // PONG :response
		{ CFRIEND , do_command_friend  }, // FRIEND username
		{ CANTI   , do_command_anti    }, // ANTI username
		{ CSAY    , do_command_say     }, // SAY :message
		{ CVECTOR , do_command_vector  }, // VECTOR username :message
		{ CWHISPER, do_command_whisper }, // WHISPER :message
		{ CTELL   , do_command_tell    }, // TELL username :message
		{ CWHOIS  , do_command_whois   }, // WHOIS username
		{ CSCAN   , do_command_scan    }, // SCAN
		{ CFRIENDS, do_command_friends }, // FRIENDS
		{ CQUIT   , do_command_quit    }, // QUIT
		{ NULL    , NULL               }
	};

	commandmap_t calls;

	struct msg_code_msg_pair msg_pairs[] = {

		{ MCSERVER  , "tchatd-" VERSION             },
		{ MCMOTD    , "message of the day"          },
		{ MCNAME    , "server name"                 },
		{ MCCREATED , "login created"               },
		{ MCVERIFIED, "login verified"              },

		{ MCFRIEND  , "friend"                      },
		{ MCREQUEST , "request"                     },
		{ MCANTI    , "anti"                        },
		{ MCDISTANCE, "distance"                    },
		{ MCRREQUEST, "request from"                },
		{ MCRANTI   , "anti from"                   },
		{ MCWHOIS   , "whois"                       },

		{ MCBEGIN   , "begin"                       },
		{ MCEND     , "end"                         },

		{ MCNEWUSER , "changed username"            },
		{ MCNEWPASS , "changed password"            },

		{ MCGOODBYE , "goodbye"                     },

		{ MCUNIMPL  , "command unimplemented"       },

		{ MCNEEDUSER, "please provide username"     },
		{ MCNEEDPASS, "please provide password"     },
		{ MCLOGIN   , "command requires login"      },

		{ MCPARAMS  , "incorrect parameters"        },
		{ MCMSG     , "missing message"             },
		{ MCCMD     , "unknown command"             },
		{ MCUSERINV , "username invalid"            },
		{ MCUSERUNK , "unknown user"                },
		{ MCNOSELF  , "cannot target self"          },
		{ MCUSEROFF , "user offline"                },

		{ MCUSER    , "username unavailable"        },
		{ MCPASS    , "incorrect password"          },
		{ MCRESET   , "start login over"            },
		{ MCNODUPES , "multiple logins not allowed" },

		{ NULL      , NULL                          }
	};

	msgmap_t messages;
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

void do_command_user(int fd, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if((long)params.size() == 0) {

		do_message(fd, MCPARAMS, CUSER);

	} else if(is_validated(fd)) {

		// do a username change

		user *user = state::users_by_fd[fd];
		const string& username = params.front();

		if(is_valid_username(username)) {

			if(state::users_by_username.find(username.c_str()) == state::users_by_username.end()) {

				// set username since its valid

				user->set_username(username);
				do_message(fd, MCNEWUSER, username.c_str());

			} else {

				do_message(fd, MCUSER);
			}

		} else {

			// otherwise say its invalid
			do_message(fd, MCUSERINV);
		}

	} else if(is_valid_partial_login(fd, params.front().c_str(), NULL)) {

		// do a login or new user creation

		if(is_validated(fd)) {

			// do login
			do_login(fd);

		} else {

			// prompt for password
			do_message(fd, MCNEEDPASS);
		}

	} else {

		do_message(fd, MCUSER);
		// dis-allow user change
	}
}
void do_command_pass(int fd, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if((long)params.size() == 0) {

		do_message(fd, MCPARAMS, CPASS);

	} else if(is_validated(fd)) {

		// do pass change

		user *user = state::users_by_fd[fd];
		const string& password = params.front();

		user->set_password(password);

		do_message(fd, MCNEWPASS);

	} else if(is_valid_partial_login(fd, NULL, params.front().c_str())) {

		if(is_validated(fd)) {

			// do login
			do_login(fd);

		} else {

			// prompt for user
			do_message(fd, MCNEEDUSER);
		}

	} else {

		// FIXME: add if too many attempts, ban
		// otherwise wrong password retard

		do_message(fd, MCPASS);
	}
}
void do_command_set(int fd, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if(is_validated(fd)) {
		do_message(fd, MCUNIMPL, CSET);
		// if VAR ok
			// if is unset
				// unset VAR
			// else
				// set VAR
	} else {
		do_message(fd, MCLOGIN, CSET);
	}
}
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
void do_command_ping(int fd, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	do_simple_cmd(CPING, fd, params, msg);
}
void do_command_pong(int fd, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	do_simple_cmd(CPONG, fd, params, msg);
}
void do_command_friend(int fd, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if(is_validated(fd)) {

		if(params.size() != 1) {

			do_message(fd, MCPARAMS, CFRIEND);

		} else if(state::users_by_username.find(params.front().c_str()) != state::users_by_username.end()) {

			// if user exists, then check if a friend request exists in the opposite direction
			// then decide if this represents a new friend request or a friend request approval

			user *user1 = state::users_by_fd[fd];
			user *user2 = state::users_by_username[params.front().c_str()];

			if(user1->id == user2->id) {
				do_message(fd, MCNOSELF, CFRIEND);
			} else {

				if(user2->friend_requests.find(user1->id) != user2->friend_requests.end()) {

					// user is in the friend_request lists of target,
					// so remove friend_request and then add as friends for both users
					// notify users of friend

					user2->friend_requests.erase(user1->id);
					user1->friends.insert(user2->id);
					user2->friends.insert(user1->id);

					do_message(fd, MCFRIEND, user2->username);

					if(user2->is_online()) {
						do_message(state::fd_by_id[user2->id], MCRREQUEST, user1->username);
						do_message(state::fd_by_id[user2->id], MCFRIEND, user1->username);
					}

				} else {
					// add as friend request
					// notify users of friend request

					user1->friend_requests.insert(user2->id);

					do_message(fd, MCREQUEST, user2->username);
					if(user2->is_online())
						do_message(state::fd_by_id[user2->id], MCRREQUEST, user1->username);
				}
			}
		} else {
			do_message(fd, MCUSERUNK, CFRIEND);
		}
	} else {
		do_message(fd, MCLOGIN, CFRIEND);
	}
}
void do_command_anti(int fd, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if(is_validated(fd)) {

		if(params.size() != 1) {

			do_message(fd, MCPARAMS, CANTI);

		} else if(state::users_by_username.find(params.front().c_str()) != state::users_by_username.end()) {

			user *user1 = state::users_by_fd[fd];
			user *user2 = state::users_by_username[params.front().c_str()];

			if(user1->id == user2->id) {
				do_message(fd, MCNOSELF, CANTI);
			} else {

				// remove any friends or friend requests and notify users

				user1->friends.erase(user2->id);
				user1->friend_requests.erase(user2->id);

				do_message(fd, MCANTI, user2->username);

				user2->friends.erase(user1->id);
				user2->friend_requests.erase(user1->id);

				if(user2->is_online())
					do_message(state::fd_by_id[user2->id], MCRANTI, user1->username);
			}

		} else {
			do_message(fd, MCUSERUNK, CANTI);
		}

	} else {
		do_message(fd, MCLOGIN, CANTI);
	}
}
void do_command_say(int fd, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	do_simple_cmd(CSAY, fd, params, msg);
}
void do_command_vector(int fd, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if(is_validated(fd)) {
		do_message(fd, MCUNIMPL, CVECTOR);
		// vector route CVECTOR
	} else {
		do_message(fd, MCLOGIN, CVECTOR);
	}
}
void do_command_whisper(int fd, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if(is_validated(fd)) {
		do_message(fd, MCUNIMPL, CWHISPER);
		// whisper route CWHISPER
	} else {
		do_message(fd, MCLOGIN, CWHISPER);
	}
}
void do_command_tell(int fd, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if(is_validated(fd)) {

		// TELL username :message

		if(params.size() != 1) {

			do_message(fd, MCPARAMS, CTELL);

		} else if(state::users_by_username.find(params.front().c_str()) != state::users_by_username.end()) {

			user *user1 = state::users_by_fd[fd];
			user *user2 = state::users_by_username[params.front().c_str()];

			if(user2->is_online()) {

				// if user is online then go ahead and relay the CTELL and set the distance to 1
				do_relay(state::fd_by_id[user2->id], user1->username, CTELL, 1, params, msg);

			} else {
				do_message(fd, MCUSEROFF, CTELL);
			}

		} else {
			do_message(fd, MCUSERUNK, CTELL);
		}

	} else {
		do_message(fd, MCLOGIN, CTELL);
	}
}
void do_command_whois(int fd, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if(is_validated(fd)) {

		user *user1 = state::users_by_fd[fd];

		if(params.size() > 1) {

			do_message(fd, MCPARAMS, CWHOIS);

		} else {

			user *user2 = NULL;

			// if theres no parameters then this is a self WHOIS, otherwise its a normal WHOIS, so check if the user exists

			if(params.size() == 0 && is_validated(fd)) {

				user2 = user1;

			} else if(state::users_by_username.find(params.front().c_str()) != state::users_by_username.end()) {

				user2 = state::users_by_username[params.front().c_str()];
			}

			if(user2 == NULL) {

				do_message(fd, MCUSERUNK, CWHOIS);

			} else {

				do_message(fd, MCBEGIN, MCWHOIS);

				do_vmessage(fd, MCWHOIS, "username %s", user2->username.c_str());

				// if the user is invisible then dont show details

				if(user2->visible) {
					do_message(fd, MCWHOIS, "visible true");
					do_vmessage(fd, MCWHOIS, "online %s", user2->is_online() ? "true" : "false");
					do_vmessage(fd, MCWHOIS, "idle %lds", user2->idle());
					do_vmessage(fd, MCWHOIS, "age %lds", user2->age());
				} else {
					do_message(fd, MCWHOIS, "visible false");
				}

				do_message(fd, MCEND, MCWHOIS);

				// let the target user know they got whois'd

				if(user2->is_online())
					do_relay(user2->get_fd(), user1->username, CWHOIS, 1, params, msg);
			}
		}

	} else {
		do_message(fd, MCLOGIN, CWHOIS);
	}
}
void do_command_scan(int fd, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if(params.size() != 0) {
		do_message(fd, MCPARAMS, CSCAN);
	} else if(is_validated(fd)) {

		user *user1 = state::users_by_fd[fd];

		do_message(fd, MCBEGIN, MCDISTANCE);

		for(nodelist_t::iterator ritr = user1->get_nodes().begin(); ritr != user1->get_nodes().end(); ritr++)
			if(ritr->get_user()->visible)
				do_vmessage(fd, MCDISTANCE, "%d %s", ritr->distance, ritr->get_user()->username.c_str());

		do_message(fd, MCEND, MCDISTANCE);

	} else {
		do_message(fd, MCLOGIN, CSCAN);
	}
}
void do_command_friends(int fd, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if(params.size() != 0) {
		do_message(fd, MCPARAMS, CFRIENDS);
	} else if(is_validated(fd)) {

		user *user = state::users_by_fd[fd];

		// do friends

		do_message(fd, MCBEGIN, MCFRIEND);

		for(friendset_t::iterator friend_itr = user->friends.begin(); friend_itr != user->friends.end(); friend_itr++)
			do_message(fd, MCFRIEND, state::users_by_id[*friend_itr]->username);

		do_message(fd, MCEND, MCFRIEND);

		// do friend requests

		do_message(fd, MCBEGIN, MCREQUEST);

		for(friendset_t::iterator request_itr = user->friend_requests.begin(); request_itr != user->friend_requests.end(); request_itr++)
			do_message(fd, MCREQUEST, state::users_by_id[*request_itr]->username);

		do_message(fd, MCEND, MCREQUEST);

		// do reverse requests

		do_message(fd, MCBEGIN, MCRREQUEST);

		for(userlist_t::iterator user_itr = state::users.begin(); user_itr != state::users.end(); user_itr++)
			for(friendset_t::iterator request_itr = (*user_itr)->friend_requests.begin(); request_itr != (*user_itr)->friend_requests.end(); request_itr++)
				if(*request_itr == user->id)
					do_message(fd, MCRREQUEST, (*user_itr)->username);

		do_message(fd, MCEND, MCRREQUEST);

	} else {
		do_message(fd, MCLOGIN, CFRIENDS);
	}
}
void do_command_quit(int fd, const paramlist_t& params, const string& msg) {

	DEBUG_PRINTF("%s ( %d [ %ld ] %s )\n", __FUNCTION__, fd, (long)params.size(), msg.c_str());

	if(params.size() != 0) {
		do_message(fd, MCPARAMS, CQUIT);
	} else {
		do_message(fd, MCGOODBYE);
		do_disconnect(fd);
	}
}
