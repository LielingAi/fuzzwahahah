#pragma once
/* sys/time.h shim for MSVC (clang-cl): QuickJS Windows 编译适配 */
#include <time.h>
#include <malloc.h>     /* alloca */
#include <windows.h>    /* FILETIME + winsock 的 struct timeval/timezone */
#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef long ssize_t;
#endif
static __inline int gettimeofday(struct timeval *tv, struct timezone *tz) {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    unsigned __int64 t = ((unsigned __int64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    t /= 10;  /* 100ns -> us */
    tv->tv_sec = (long)(t / 1000000ULL - 11644473600ULL);
    tv->tv_usec = (long)(t % 1000000ULL);
    (void)tz;
    return 0;
}
