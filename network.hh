#ifndef MESSAGE_HH
#define MESSAGE_HH

#include <string>

#include "types.hh"

// application layer

void do_vmessage(int fd, const char *msg_code, const char *fmt, ...);
void do_message(int fd, const char *msg_code, const std::string& msg_string);
void do_message(int fd, const char *msg_code, const char *msg);
void do_message(int fd, const char *msg_code);

void do_login(int fd);

void do_relay(int fd, const std::string& username, const char *command, unsigned int distance, const paramlist_t& params, const std::string& msg);

void do_simple_cmd(const char *cmd, int fd, const paramlist_t& params, const std::string& msg);

// socket layer

void do_disconnect(int fd);
void do_send(int fd, const void *buf, size_t len, int flags);

// auth

bool is_valid_partial_login(int fd, const char *username, const char *password);
bool is_valid_username(const std::string& username);
bool is_validated(int fd);

#endif
