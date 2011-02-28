#ifndef COMMANDS_HH
#define COMMANDS_HH

#include <map>

#include "types.hh"

typedef void command_fn_t(int fd, const paramlist_t& params, const std::string& msg);
typedef std::map<const char *, command_fn_t *, strcase_compar> commandmap_t;
typedef std::map<const char *,const char *, strcase_compar> msgmap_t;

command_fn_t do_command_anti;
command_fn_t do_command_friend;
command_fn_t do_command_friends;
command_fn_t do_command_user;
command_fn_t do_command_pass;
command_fn_t do_command_ping;
command_fn_t do_command_pong;
command_fn_t do_command_quit;
command_fn_t do_command_say;
command_fn_t do_command_scan;
command_fn_t do_command_set;
command_fn_t do_command_tell;
command_fn_t do_command_vector;
command_fn_t do_command_whisper;
command_fn_t do_command_whois;

namespace command {

#define CUSER    "user"
#define CPASS    "pass"
#define CSET     "set"
#define CPING    "ping"
#define CPONG    "pong"
#define CFRIEND  "friend"
#define CANTI    "anti"
#define CSAY     "say"
#define CVECTOR  "vector"
#define CWHISPER "whisper"
#define CTELL    "tell"
#define CWHOIS   "whois"
#define CSCAN    "scan"
#define CFRIENDS "friends"
#define CQUIT    "quit"

	extern struct command_name_fptr_pair {

		const char *command_name;
		const command_fn_t *command_fptr;

	} command_pairs[];

// information messages
#define MCSERVER   "000"
#define MCMOTD     "001"
#define MCNAME     "002"
#define MCCREATED  "003"
#define MCVERIFIED "004"

#define MCNEWUSER  "051"
#define MCNEWPASS  "052"

#define MCFRIEND   "061"
#define MCREQUEST  "062"
#define MCANTI     "063"
#define MCDISTANCE "064"
#define MCRREQUEST "065"
#define MCRANTI    "066"
#define MCWHOIS    "067"

#define MCBEGIN    "080"
#define MCEND      "081"

#define MCGOODBYE  "099"

// warning messages
#define MCPARAMS   "101"
#define MCMSG      "102"
#define MCCMD      "103"
#define MCUSERINV  "104"
#define MCUNIMPL   "105"
#define MCUSERUNK  "106"
#define MCNOSELF   "107"
#define MCNODUPES  "108"
#define MCUSEROFF  "109"

// rate limit messages

// permissions messages
#define MCNEEDUSER "201"
#define MCNEEDPASS "202"
#define MCLOGIN    "203"

// authentication messages
#define MCUSER     "301"
#define MCPASS     "302"
#define MCRESET    "303"

	extern struct msg_code_msg_pair {
		const char *msg_code;
		const char *msg_str;
	} msg_pairs[];

	extern commandmap_t calls;
	extern msgmap_t messages;
}
					
#endif
