/* Copyright (c) 2025 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include "version.h"

#include "reference.h"

#define TEST_COUNT 10000000

uint64_t tab1[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
uint64_t tab2[16] = { 1, 2, 3, 4, 5, 6, 7, 8 };
uint64_t tab3[16] = { 1, 2, 3, 4, 5, 6, 7, 8 };

uint64_t getnow(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (ts.tv_sec * 1000000000LLU) + ts.tv_nsec;
}

void speedtest()
{
  double warm = 0;
  for (size_t i = 0; i < 1000; i++)
    warm += sqrt(i);

  uint64_t t1 = getnow();
  for (size_t i = 0; i < TEST_COUNT; i++) {
    kit_sha512_iterate_asm(tab1, tab2);
  }
  uint64_t t2 = getnow();
  for (size_t i = 0; i < TEST_COUNT; i++) {
    kit_sha512_iterate_c(tab3, tab2);
  }
  uint64_t t3 = getnow();

  printf("asm: %lld\nc:   %lld\n", t2 - t1, t3 - t2);
  double p = (double)(t2 - t1) / (double)(t3 - t2);
  printf("%:   %f\n", (1. - p) * 100.);
}

int main(int argc, char * argv[])
{
  for (size_t i = 0; i < 8; i++) {
    tab3[i] = tab1[i] = rand();
  }
  for (size_t i = 0; i < 16; i++)
    tab2[i] = rand();

  kit_sha512_iterate_asm(tab1, tab2);
  kit_sha512_iterate_c(tab3, tab2);

  printf("%d\n", memcmp(tab1, tab3, sizeof(tab1)));

  speedtest();

  return 0;
}
