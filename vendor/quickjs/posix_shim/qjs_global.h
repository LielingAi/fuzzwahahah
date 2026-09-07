#pragma once
/* qjs_global.h - clang-cl /FI 强制包含: QuickJS Windows 编译全局适配 */
#include <malloc.h>   /* alloca */
#include <sys/stat.h>
#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef long ssize_t;
#endif
#ifndef PATH_MAX
#define PATH_MAX 260
#endif
#ifndef popen
#define popen _popen
#define pclose _pclose
#endif
#ifndef S_ISDIR
#define S_ISDIR(m) (((m) & _S_IFMT) == _S_IFDIR)
#endif
#ifndef S_ISREG
#define S_ISREG(m) (((m) & _S_IFMT) == _S_IFREG)
#endif
#ifndef S_ISCHR
#define S_ISCHR(m) (((m) & _S_IFMT) == _S_IFCHR)
#endif
#ifndef S_ISFIFO
#define S_ISFIFO(m) (((m) & _S_IFMT) == _S_IFIFO)
#endif
#ifndef S_IFIFO
#define S_IFIFO _S_IFIFO
#endif
#ifndef S_IFBLK
#define S_IFBLK 0x6000  /* POSIX 占位值, Windows 无块设备概念 */
#endif
#ifndef S_IFSOCK
#define S_IFSOCK 0xC000
#endif
#ifndef S_IFLNK
#define S_IFLNK 0xA000
#endif
