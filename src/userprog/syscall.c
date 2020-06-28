#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "filesys/inode.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

#include <string.h>

static void syscall_handler (struct intr_frame *);
static void process_terminate (int);
static int check_user_ptr (void * p);

#define MAX_PAGES_IN_FILE 8
#define MAX_FILE_NAME_LEN 64
#define MAX_FILES 128
#define MAX_ARGS_ON_USER_STACK 4

typedef struct fd_file {
  int fd;
  char file_name[MAX_FILE_NAME_LEN];
  struct file * file;
  int is_open; // 0 if this fd is closed, 1 if this fd is open
  int pid; // pid of owning process
} fd_file_t;

// maintain static table of file descriptors out of laziness
static struct lock fd_table_lock;
static fd_file_t fd_table[MAX_FILES];
static int fd_count; // never recycle these

void init_fd_table(void) {
  lock_init(&fd_table_lock);
  int i;
  memset(fd_table,0,sizeof(fd_file_t)*MAX_FILES);
  for ( i = 0; i < MAX_FILES; ++i ) {
    fd_table[i].fd = -1;
    fd_table[i].pid = -1;
  }
  // must start at 2
  // 0 is stdin
  // 1 is stdout
  fd_count = 2;  
}

static void destroy_fd_table(void) {
  lock_acquire(&fd_table_lock);
  int i;
  int success;
  for ( i = 0; i < MAX_FILES; ++i ) {
    const char * const file_name = fd_table[i].file_name;
    if ( file_name != NULL && strcmp(file_name,"") != 0 ) {
      success = filesys_remove(file_name);
      ASSERT(success);
    }
  }
  lock_release(&fd_table_lock);
}

static int create_fd(const char * file_name, struct file * file) {
  int i;
  int fd;
  int fd_idx;

  ASSERT ( file_name != NULL );
  if ( strcmp(file_name,"") == 0 ) {
    return -1;
  }
  else if ( strlen(file_name)+1 >= MAX_FILE_NAME_LEN) {
    return -1;
  }
  
  lock_acquire(&fd_table_lock);
  
  fd_idx = -1;
  for ( i = 0; i < MAX_FILES; ++i ) {
    if ( fd_table[i].fd == -1 ) {
      fd_idx = i;
      break;
    }
  }
  
  /* printf("create_fd fd_idx: %d\n",fd_idx); */
  
  if ( fd_idx == -1 ) {
    printf("ERROR: fd table is full\n");
    fd = -1;
    goto create_fd_done;
  }

  ASSERT( file != NULL );
  
  fd = fd_count; // must start at 2
  ++fd_count;

  fd_table[fd_idx].fd = fd;
  strlcpy(fd_table[fd_idx].file_name,file_name,MAX_FILE_NAME_LEN);
  fd_table[fd_idx].file = file;
  fd_table[fd_idx].is_open = 1; // ONLY call from open_fd
  fd_table[fd_idx].pid = thread_pid();

  /* printf("fd_table[%d] %p fd %d\n",fd_idx,&fd_table[fd_idx],fd_table[fd_idx].fd); */
  
 create_fd_done:
  lock_release(&fd_table_lock);

  return fd;
}

static int open_fd(const char * const file_name) {
  int fd;
  struct file * file = filesys_open(file_name); // I assume this is thread safe?
  if ( file == NULL ) {
    fd = -1;
    return fd;
  }
  
  fd = create_fd(file_name,file);
  

  return fd;
}

static void clear_fd(struct fd_file * fd_file) {
  fd_file->fd = -1;
  fd_file->file_name[0] = 0;
  fd_file->file = NULL;
  fd_file->is_open = 0;
  fd_file->pid = -1;
}

static void close_fd(int fd) {
  lock_acquire(&fd_table_lock);

  int i;
  int fd_idx = -1;
  for ( i = 0; i < MAX_FILES; ++i ) {
    if ( fd_table[i].fd == fd ) {
      fd_idx = i;
    }
  }
  
  if ( fd_idx != -1 ) {
    clear_fd(&fd_table[fd_idx]);
  }
  
  lock_release(&fd_table_lock);
}

static int fd_to_fd_idx_no_lock(int fd) {
  int i;
  int fd_idx = -1;
  for ( i = 0; i < MAX_FILES; ++i ) {
    if ( fd_table[i].fd == fd ) {
      fd_idx = i;
      break;
    }
  }
  return fd_idx;
}

static int is_valid_fd_entry_no_lock(int fd_idx) {
  if ( fd_idx == -1 ) {
    return 0;
  }
  else if ( fd_table[fd_idx].file == NULL ||
            fd_table[fd_idx].is_open == 0 ) {
    return 0;
  }
  return 1;
}

static int read_fd(int fd, void * p, unsigned sz) {
  lock_acquire(&fd_table_lock);
  int fd_idx = fd_to_fd_idx_no_lock(fd);
  int ret = is_valid_fd_entry_no_lock(fd_idx);
  if ( ret == 1 ) {
    ASSERT(fd_table[fd_idx].pid == thread_pid());  
    ret = file_read(fd_table[fd_idx].file,p,sz);
  }
  lock_release(&fd_table_lock);
  return ret;
}

static int filesize_fd(int fd) {
  lock_acquire(&fd_table_lock);
  int fd_idx = fd_to_fd_idx_no_lock(fd);
  int ret = is_valid_fd_entry_no_lock(fd_idx);
  if ( ret == 1 ) {
    ASSERT(fd_table[fd_idx].file != NULL);
    ret = file_length(fd_table[fd_idx].file);
  }
  lock_release(&fd_table_lock);
  return ret;
  
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void process_terminate (int status) {
  printf("%s: exit(%d)\n",thread_current()->process_name,status);
  destroy_fd_table();
  process_exit();
  thread_exit ();  
}

static int check_user_ptr (void * p_) {
  const char * p = p_;
  int i;
  int success;
  const int word_size = sizeof(void *);
  if ( p == NULL ) {
    return 1;
  }
  else {
    success = 0;
    
    for ( i = word_size-1; i; --i ) {
      success = is_kernel_vaddr(p+i); // make sure every byte is also in user space
      if ( success ) {
        break;
      }
    }
    
    if ( success ) {
      return success;
    }
    
    for ( i = word_size-1; i; --i ) {
      success = (pagedir_get_page(thread_current ()->pagedir,p+i) == NULL);
      if ( success ) {
        break;
      }
    }
    return success;
  }
}

static int check_user_ptr_with_terminate(void * p) {
  if (check_user_ptr(p)) {
    struct thread * cur = thread_current();
    set_child_process_status(cur->parent_pid,thread_pid(),(process_status_e)PROCESS_KILLED);
    process_terminate(-1);
    return 1;
  }
  else {
    return 0;
  }
}

static int get_num_args(int syscall_no) {
  int num_args;
  if ( syscall_no == SYS_HALT ) {
    num_args = 0;
  }
  else if (syscall_no == SYS_EXIT ) {
    num_args = 1;
  }
  else if ( syscall_no == SYS_EXEC ) {
    num_args = 1;
  }
  else if ( syscall_no == SYS_WAIT ) {
    num_args = 1;
  }
  else if ( syscall_no == SYS_CREATE ) {
    num_args = 2;
  }
  else if ( syscall_no == SYS_REMOVE ) {
    num_args = 1;
  }
  else if ( syscall_no == SYS_OPEN ) {
    num_args = 1;
  }
  else if ( syscall_no == SYS_FILESIZE ) {
    num_args = 1;
  }
  else if ( syscall_no == SYS_READ ) {
    num_args = 3;
  }
  else if ( syscall_no == SYS_WRITE ) {
    num_args = 3;
  }
  else if ( syscall_no == SYS_SEEK ) {
    num_args = 2;
  }
  else if ( syscall_no == SYS_TELL ) {
    num_args = 1;
  }
  else if ( syscall_no == SYS_CLOSE ) {
    num_args = 1;
  }
  else {
    ASSERT(false);
    num_args = 0;
  }
  return num_args;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{

  int fd;
  
  int tmp_int;
  char * tmp_char_ptr;

  int success;
  
  int syscall_no;
  int status;
  size_t word_size = sizeof(void *);
  struct thread * cur = thread_current();
  char * esp = f->esp; // user's stack pointer
                       // cast to char * to have 1 byte type
  
  // verify that it's a good pointer
  if ( check_user_ptr_with_terminate(esp) ) {
    return;
  }
  
  syscall_no = *((int *)esp);
  /* printf("syscall_no: %d\n",syscall_no); */
  esp += word_size;

  int num_args = get_num_args(syscall_no);
  void * user_args[MAX_ARGS_ON_USER_STACK];
  memset(user_args,0,MAX_ARGS_ON_USER_STACK*sizeof(void *));

  // only do this for syscall read and file size for now
  for ( int i = 0; i < num_args; ++i ) {
    if ( check_user_ptr_with_terminate(esp) ) {
      return;
    }
    user_args[i] = *((void **)esp);
    esp += word_size;
  }
  
  if ( syscall_no == SYS_HALT ) {
    shutdown_power_off();
  }
  else if (syscall_no == SYS_EXIT ) {
    status = (int)user_args[0];
    set_child_process_status(cur->parent_pid,thread_pid(),(process_status_e)status);
    process_terminate(status);
    return;
  }
  else if ( syscall_no == SYS_EXEC ) {
  }
  else if ( syscall_no == SYS_WAIT ) {
  }
  else if ( syscall_no == SYS_CREATE ) {
    tmp_char_ptr = (char *)user_args[0];
    tmp_int = (int)user_args[1];

    if ( check_user_ptr_with_terminate((void *)tmp_char_ptr /*file_name*/) ) {
      return;
    }
    
    success = filesys_create(tmp_char_ptr,tmp_int);
    f->eax = success;
  }
  else if ( syscall_no == SYS_REMOVE ) {
  }
  else if ( syscall_no == SYS_OPEN ) {
    tmp_char_ptr = (char *)user_args[0];    
    if ( check_user_ptr_with_terminate((void *)tmp_char_ptr /*file_name*/) ) {
      return;
    }
    else {
      fd = open_fd(tmp_char_ptr);
    }
    f->eax = fd;
  }
  else if ( syscall_no == SYS_FILESIZE ) {
    int fd = (int)user_args[0];
    f->eax = filesize_fd(fd);
  }
  else if ( syscall_no == SYS_READ ) {
    int fd = (int)user_args[0];
    void * p = user_args[1];
    unsigned sz = (unsigned)user_args[2];
    if ( check_user_ptr_with_terminate(p) ) {
      return;
    }
    if ( fd == 0 ) {
      // read from keyboard
      unsigned num_read = 0;
      char key;
      while ( num_read < sz ) {
        key = input_getc();
        memset(p,key,1);
        ++num_read;
      }
      f->eax = sz;
    }
    else {
      f->eax = read_fd(fd,p,sz);      
    }
  }
  else if ( syscall_no == SYS_WRITE ) {
    int fd = (int)user_args[0];
    void * p = user_args[1];
    unsigned size = (unsigned)user_args[2];
    if ( check_user_ptr_with_terminate(p) ) {
      return;
    }
    
    if ( fd == 1 ) {
      putbuf(p,size);
    }
    else {
      // deal with file descriptors later
    }
    f->eax = size;
  }
  else if ( syscall_no == SYS_SEEK ) {
  }
  else if ( syscall_no == SYS_TELL ) {
  }
  else if ( syscall_no == SYS_CLOSE ) {
    int fd = (int)user_args[0];
    close_fd(fd);
  }
  else {
    printf("didn't get a project 2 sys call\n");
    ASSERT(false);
    process_terminate(1);
  }  
}
