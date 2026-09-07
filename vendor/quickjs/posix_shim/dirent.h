#pragma once
/* dirent.h shim for MSVC (clang-cl): QuickJS Windows 编译适配
   opendir/readdir/closedir 用 FindFirstFile 实现 */
#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

struct dirent {
    char d_name[MAX_PATH];
};

typedef struct DIR {
    HANDLE hFind;
    WIN32_FIND_DATAA ffd;
    struct dirent entry;
    int first;
} DIR;

static __inline DIR *opendir(const char *path) {
    DIR *d = (DIR *)malloc(sizeof(DIR));
    if (!d) return NULL;
    char pattern[MAX_PATH];
    snprintf(pattern, MAX_PATH, "%s\*", path);
    d->hFind = FindFirstFileA(pattern, &d->ffd);
    if (d->hFind == INVALID_HANDLE_VALUE) { free(d); return NULL; }
    d->first = 1;
    return d;
}

static __inline struct dirent *readdir(DIR *d) {
    if (d->first) {
        d->first = 0;
    } else if (!FindNextFileA(d->hFind, &d->ffd)) {
        return NULL;
    }
    strcpy(d->entry.d_name, d->ffd.cFileName);
    return &d->entry;
}

static __inline int closedir(DIR *d) {
    FindClose(d->hFind);
    free(d);
    return 0;
}
