/* AuroraOS system call ABI — the single source of truth shared by the kernel
 * and user space. Do not renumber existing calls; only append new ones.
 *
 * Calling convention (int 0x80):
 *   eax = syscall number
 *   ebx = arg1, ecx = arg2, edx = arg3
 *   eax = return value (negative on error)
 */
#pragma once

#define SYS_PUTC   1    /* putc(char c)                              */
#define SYS_YIELD  2    /* yield()                                   */
#define SYS_EXIT   3    /* exit(int code)            -> no return    */
#define SYS_FORK   4    /* fork()                    -> pid / 0       */
#define SYS_EXEC   5    /* exec(const char *path, char **argv)       */
#define SYS_WAIT   6    /* wait(int *status)         -> pid          */
#define SYS_OPEN   7    /* open(const char *path, int flags) -> fd   */
#define SYS_READ   8    /* read(int fd, void *buf, uint len) -> n    */
#define SYS_WRITE  9    /* write(int fd, const void *buf, uint len)  */
#define SYS_CLOSE  10   /* close(int fd)                             */
#define SYS_GETPID 11   /* getpid() -> pid                           */
#define SYS_PIPE   12   /* pipe(int fd[2])           -> 0 / -1       */
#define SYS_DUP2   13   /* dup2(int oldfd, int newfd)-> newfd        */
#define SYS_SBRK   14   /* sbrk(int incr)            -> old brk      */
#define SYS_MSGSEND 15  /* msgsend(pid, buf, len)    -> 0 / -1       */
#define SYS_MSGRECV 16  /* msgrecv(buf, len, &from)  -> n (blocks)   */
#define SYS_REGISTER 17 /* register(name)            -> 0 / -1       */
#define SYS_LOOKUP  18  /* lookup(name)              -> pid / -1     */

#define SYS_MAX    19   /* one past the last valid syscall number    */
