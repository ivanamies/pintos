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

#include <string.h>

static void syscall_handler (struct intr_frame *);
static void process_terminate (int);
static int check_user_ptr (char * p);

#define MAX_PAGES_IN_FILE 8
#define MAX_FILE_NAME_LEN 64
#define MAX_FILES 128

typedef struct fd_file {
  int fd;
  char file_name[MAX_FILE_NAME_LEN];
  struct file * file;
  /* int sz; */
  /* int pos; */
  /* void * pages[MAX_PAGES_IN_FILE]; */
  
} fd_file_t;

// maintain static table of file descriptors out of laziness
static struct lock fd_table_lock;
static fd_file_t fd_table[MAX_FILES];
static int fd_count; // never recycle these

void init_fd_table(void) {
  lock_init(&fd_table_lock);
  int i;
  int success;
  memset(fd_table,0,sizeof(fd_file_t)*MAX_FILES);
  for ( i = 0; i < MAX_FILES; ++i ) {
    fd_table[i].fd = -1;
  }
  fd_count = 0;
  
  // create some inodes in sector 3
  // ... I don't know man
  for ( i = 0; i < 10; ++i ) {
    printf("what\n");
    success = inode_create(3, 1024);
    if ( !success ) {
      ASSERT (false && "inode create failed\n");
    }
  }
}

static void destroy_fd_table(void) {
  lock_acquire(&fd_table_lock);
  int i;
  for ( i = 0; i < MAX_FILES; ++i ) {
    if ( fd_table[i].file != NULL ) {
      file_close(fd_table[i].file);
    }
  }
  lock_release(&fd_table_lock);
}

static int create_fd(const char * file_name, size_t sz) {
  lock_acquire(&fd_table_lock);

  int i, fd;
  
  // find an empty file slow
  int fd_idx = -1;
  for ( i = 0; i < MAX_FILES; ++i ) {
    if (fd_table[i].fd == -1) {
      fd_idx = i;
      break;
    }
  }

  if ( fd_idx == -1 ) {
    return -1;
  }
  
  ++fd_count;
  fd = fd_count;
  
  fd_table[fd_idx].fd = fd;
  strlcpy(fd_table[fd_idx].file_name,file_name,MAX_FILE_NAME_LEN);
  
  // what the fuck
  struct inode * inode = inode_open(3); // picked 3 at random
  // just completely ignore sz
  // inode is free'd when file is closed
  fd_table[fd_idx].file = file_open(inode);
  
  lock_release(&fd_table_lock);

  return fd;
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

static int check_user_ptr (char * p) {
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
    
    fd = create_fd(tmp_char_ptr,tmp_int);
    if (fd == -1 ) {
      f->eax = 0;
    }
    else {
      f->eax = 1;
    }
  }
  else if ( syscall_no == SYS_REMOVE ) {
  }
  else if ( syscall_no == SYS_OPEN ) {
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
  }
  else {
    printf("didn't get a project 2 sys call\n");
    ASSERT(false);
    process_terminate(1);
  }  
}
