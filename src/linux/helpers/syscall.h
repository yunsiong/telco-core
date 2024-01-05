#ifndef __TELCO_SYSCALL_H__
#define __TELCO_SYSCALL_H__

#include <unistd.h>
#include <sys/syscall.h>

#define telco_syscall_0(n)          telco_syscall_4 (n, 0, 0, 0, 0)
#define telco_syscall_1(n, a)       telco_syscall_4 (n, a, 0, 0, 0)
#define telco_syscall_2(n, a, b)    telco_syscall_4 (n, a, b, 0, 0)
#define telco_syscall_3(n, a, b, c) telco_syscall_4 (n, a, b, c, 0)

ssize_t telco_syscall_4 (size_t n, size_t a, size_t b, size_t c, size_t d);

#endif
