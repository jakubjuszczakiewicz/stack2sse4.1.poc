/* Copyright (c) 2024 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "version.h"
#include <string.h>

#define VERSION_MAJOR 0
#define VERSION_MINOR 0
#define VERSION_PATCH 1
#define VERSION_SUBSTR ""

#define STR(s) #s
#define MAKE_VER(ma, mi, pa, st) (STR(ma) "." STR(mi) "." STR(pa) st)

#define VERSION_STR MAKE_VER(VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH, VERSION_SUBSTR)

uint16_t kit_pov_stack_version[3] = { VERSION_MAJOR, VERSION_MINOR,
    VERSION_PATCH };
size_t kit_pov_stack_version_str_len = strlen(VERSION_STR);
char kit_pov_stack_version_str[] = VERSION_STR;
