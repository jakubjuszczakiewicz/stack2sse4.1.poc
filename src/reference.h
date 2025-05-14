/* Copyright (c) 2024 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

#include <stdint.h>

void kit_sha512_iterate_c(uint64_t * ctx, const uint64_t * data);
void kit_sha512_iterate_asm(uint64_t * ctx, const uint64_t * data);
