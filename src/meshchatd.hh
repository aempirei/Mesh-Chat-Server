#ifndef MESHCHATD_HH
#define MESHCHATD_HH

#include <map>
#include <string>

#include "config.hh"
#include "state.hh"
#include "types.hh"

#define PROGRAM "Mesh Chat Server"
#define VERSION "1.0"
#define DEBUG_MESSAGE     DEBUG_MESSAGE2(__FUNCTION__)
#define DEBUG_MESSAGE2(a) config::debug && puts(a)
#define DEBUG_PRINTF      config::debug && printf

void handle_error(const char *str);
int randomrange(int a, int b);

#endif
