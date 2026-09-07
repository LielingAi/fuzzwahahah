/* reprl_win.h - QuickJS Fuzzilli REPRL 通道原语接口（Windows） */
#ifndef REPR_L_WIN_H
#define REPR_L_WIN_H

#ifdef _WIN32

int reprl_handshake(void);
int reprl_open_script_channel(void);
const char *reprl_script_map(void);
int reprl_open_coverage(void);
int reprl_read_ctrl(void *buf, int n);
int reprl_write_ctrl(const void *buf, int n);

#endif /* _WIN32 */
#endif
