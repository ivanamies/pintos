#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

struct file;

void syscall_init (void);

void init_fd_table (void);

int fd_open(const char * const);
void fd_destroy(int pid);

int fd_read(int fd, void * p, unsigned sz);
int fd_filesize(int fd);
int fd_write(int fd, void * p, unsigned sz);
void fd_seek(int fd, unsigned pos);
int fd_tell(int fd);

void fd_deny_write(int fd);

// functions that basically shouldn't exist
// and are hacks
struct file * fd_get_file(int fd);
void debug_fd_table(int aux);

#endif /* userprog/syscall.h */
