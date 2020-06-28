#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
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

typedef struct fd_file {
  int fd;
  char file_name[MAX_FILE_NAME_LEN];
  struct file * file;
  int sz;
  int pos;
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

static int create_fd(const char * file_name, size_t sz, struct file * file) {
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
    }
  }
    
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
  fd_table[fd_idx].sz = sz;
  fd_table[fd_idx].pos = 0;
  fd_table[fd_idx].file = file;
  fd_table[fd_idx].is_open = 1; // ONLY call from open_fd
  fd_table[fd_idx].pid = thread_pid();
    
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
    
  fd = create_fd(file_name,file_length(file),file);
  

  return fd;
}

static void clear_fd(struct fd_file * fd_file) {
  fd_file->fd = -1;
  fd_file->file_name[0] = 0;
  fd_file->sz = 0;
  fd_file->pos = 0;
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

  if ( syscall_no == SYS_HALT ) {
    shutdown_power_off();
  }
  else if (syscall_no == SYS_EXIT ) {
    if ( check_user_ptr_with_terminate(esp) ) {
      return;
    }
    status = *((int *)esp);
    esp += word_size;
    set_child_process_status(cur->parent_pid,thread_pid(),(process_status_e)status);
    process_terminate(status);
    return;
  }
  else if ( syscall_no == SYS_EXEC ) {
  }
  else if ( syscall_no == SYS_WAIT ) {
  }
  else if ( syscall_no == SYS_CREATE ) {

    {
      if ( check_user_ptr_with_terminate(esp) ) {
        return;
      }
      tmp_char_ptr = *((char **)esp);
      esp += word_size;
    }

    {
      if ( check_user_ptr_with_terminate(esp) ) {
        return;
      }
      tmp_int = *((int *)esp);
      esp += word_size;
    }

    if ( check_user_ptr_with_terminate((void *)tmp_char_ptr /*file_name*/) ) {
      return;
    }
    
    success = filesys_create(tmp_char_ptr,tmp_int);
    f->eax = success;
  }
  else if ( syscall_no == SYS_REMOVE ) {
  }
  else if ( syscall_no == SYS_OPEN ) {
    {
      if ( check_user_ptr_with_terminate(esp) ) {
        return;
      }
      tmp_char_ptr = *((char **)esp);
      esp += word_size;
    }
    if ( check_user_ptr_with_terminate((void *)tmp_char_ptr /*file_name*/) ) {
      return;
    }
    else {
      fd = open_fd(tmp_char_ptr);
    }
    f->eax = fd;
  }
  else if ( syscall_no == SYS_FILESIZE ) {
  }
  else if ( syscall_no == SYS_READ ) {
    // blah
  }
  else if ( syscall_no == SYS_WRITE ) {
    if ( check_user_ptr_with_terminate(esp) ) {
      return;
    }
    int fd = *((int *)esp);
    esp += word_size;
    if ( check_user_ptr_with_terminate(esp) ) {
      return;
    }
    const void * buffer = *((void **)esp);
    esp += word_size;
    if ( check_user_ptr_with_terminate(esp) ) {
      return;
    }
    unsigned size = *((unsigned *)esp);
    esp += word_size;
    /* printf("fd: %d buffer: %p size: %d\n",fd,buffer,(int)size); */
    if ( fd == 1 ) {
      putbuf(buffer,size);
    }
    else {
      // deal with file descriptors later
    }
  }
  else if ( syscall_no == SYS_SEEK ) {
  }
  else if ( syscall_no == SYS_TELL ) {
  }
  else if ( syscall_no == SYS_CLOSE ) {
    {
      if ( check_user_ptr_with_terminate(esp) ) {
        return;
      }
      tmp_int = *((int *)esp);
      esp += word_size;
    }
    int fd = tmp_int;
    close_fd(fd);
  }
  else {
    printf("didn't get a project 2 sys call\n");
    ASSERT(false);
    process_terminate(1);
  }  
}
