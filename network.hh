#ifndef MESSAGE_HH
#define MESSAGE_HH

void do_vmessage(int fd, const char *msg_code, const char *fmt, ...);
void do_message(int fd, const char *msg_code, const std::string& msg_string);
void do_message(int fd, const char *msg_code, const char *msg);
void do_message(int fd, const char *msg_code);

void do_login(int fd);
void do_disconnect(int fd);
void do_relay(int fd, const std::string& username, const char *command, unsigned int distance, const paramlist_t& params, const std::string& msg);

bool is_valid_partial_login(int fd, const char *username, const char *password);
bool is_valid_username(const std::string& username);
bool is_validated(int fd);


#endif
