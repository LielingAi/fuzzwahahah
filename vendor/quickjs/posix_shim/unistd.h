#pragma once
/* unistd.h shim for MSVC (clang-cl): QuickJS Windows 编译适配 */
#include <io.h>
#include <process.h>
#include <stdlib.h>
#include <malloc.h>   /* alloca */
#include <direct.h>
#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#endif
#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef long ssize_t;
#endif
