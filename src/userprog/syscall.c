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
  process_exit();
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
    process_terminate();
    return;
  }
  
  syscall_no = *((int *)esp);
  esp += word_size;
  
  if ( syscall_no == SYS_HALT ) {
  }
  else if (syscall_no == SYS_EXIT ) {
    status = *((int *)esp);
    esp += word_size;
    cur->process_status = status;
    // set parent's waiting_for_status to indicate exit
    if (cur->parent_process != NULL ) {
      // 0 is PROCESS_GOOD_EXIT and EXIT_SUCCESS
      // 1 is PROCESS_BAD_EXIT and EXIT_FAILURE
      cur->parent_process->waiting_for_status = status;
    }
    printf("%s: exit(%d)\n",cur->process_name,cur->process_status);
    process_terminate();
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
