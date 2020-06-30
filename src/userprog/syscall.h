#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

void init_fd_table (void);
int open_fd(const char * const);
void deny_write_fd(int fd);

#endif /* userprog/syscall.h */
