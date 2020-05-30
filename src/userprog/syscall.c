#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

static void syscall_handler (struct intr_frame *);
static void process_terminate (void);
static int check_user_ptr ( void * p);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void process_terminate () {
  printf("===tagiamies 5\n");
  process_exit();
  printf("===tagiamies 99\n");
  thread_exit ();  
}

// apparently doesn't work...
static int check_user_ptr ( void * p) {
  if ( p == NULL ) {
    return 1;
  }
  else if ( is_kernel_vaddr(p) ) {
    return 1;
  }
  else if ( pagedir_get_page(thread_current ()->pagedir,p) == NULL ) {
    return 1;
  }
  else {
    return 0;
  }
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  /* printf ("system call!\n"); */

  int syscall_no;
  int status;
  size_t word_size = sizeof(void *);
  struct thread * cur = thread_current();
  char * esp = f->esp; // user's stack pointer
                       // cast to char * to have 1 byte type

  /* int success = 1; */
  
  // verify that it's a good pointer
  if (check_user_ptr(esp)) {
    printf("invalid address\n");
    set_child_process_status(cur->parent_pid,thread_pid(),(process_status_e)PROCESS_KILLED);
    process_terminate();
    return;
  }
  
  syscall_no = *((int *)esp);
  esp += word_size;
  
  if ( syscall_no == SYS_HALT ) {
  }
  else if (syscall_no == SYS_EXIT ) {
    printf("===tagiamies 2\n");

    status = *((int *)esp);
    esp += word_size;
    set_child_process_status(cur->parent_pid,thread_pid(),(process_status_e)status);
    printf("===tagiamies 3\n");
    process_terminate();
    printf("===tagiamies 4\n");
    return;
  }
  else if ( syscall_no == SYS_EXEC ) {
  }
  else if ( syscall_no == SYS_WAIT ) {
  }
  else if ( syscall_no == SYS_CREATE ) {
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
    int fd = *((int *)esp);
    esp += word_size;
    const void * buffer = *((void **)esp);
    esp += word_size;
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
    process_terminate();
  }  
}
