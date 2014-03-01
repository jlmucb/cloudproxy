//
//  File: timing.cc
//  Description: real time counter, etc
//
//
//  Copyright (c) John Manferdelli.  All rights reserved.
//
// Use, duplication and disclosure of this file and derived works of
// this file are subject to and licensed under the Apache License dated
// January, 2004, (the "License").  This License is contained in the
// top level directory originally provided with the CloudProxy Project.
// Your right to use or distribute this file, or derived works thereof,
// is subject to your being bound by those terms and your use indicates
// consent to those terms.
//
// If you distribute this file (or portions derived therefrom), you must
// include License in or with the file and, in the event you do not include
// the entire License in the file, the file must contain a reference
// to the location of the License.

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include "../common.h"

inline u64 ReadRTC() {
  u64  out= 0ULL;
  u64* pointer= &out;

  asm volatile (
        "\trdtsc\n"
        "\tmovq     %[pointer],%%rcx\n"
        "\tmovl     %%eax, (%%rcx)\n"
        "\tmovl     %%edx, 4(%%rcx)\n"
    :[out] "=g" (out)
    :[pointer] "m" (pointer)
    : "%rcx", "%eax", "%edx");
    return out;
}


u64 CalibrateRTC() {
  u64     rtc_start, rtc_finish;
  time_t  start, finish;
  double  elapsedseconds= 0.0;
  u64     cycles_per_second= 0ULL;

  time(&start);
  rtc_start= ReadRTC();
  sleep(4);
  rtc_finish= ReadRTC();
  time(&finish);
  elapsedseconds= difftime(finish, start);
  cycles_per_second= (u64)(((double)(rtc_finish-rtc_start))/elapsedseconds);
#ifdef TEST
  printf("%12.6lf elapsed seconds %ld start, %ld finish\n", 
         elapsedseconds, (long int)rtc_start, (long int)rtc_finish);
#endif
  return cycles_per_second;
}


int main(int an, char** av) {
  u64 cycles_per_second= CalibrateRTC();

  printf("%ld cycles per second on this machine\n", (long int) cycles_per_second);
  return 0;
}




