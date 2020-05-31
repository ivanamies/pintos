#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

static void syscall_handler (struct intr_frame *);
static void process_terminate (int);
static int check_user_ptr (char * p);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void process_terminate (int status) {
  printf("%s: exit(%d)\n",thread_current()->process_name,status);
  process_exit();
  thread_exit ();  
}

// apparently doesn't work...
static int check_user_ptr (char * p) {
  if ( p == NULL ) {
    return 1;
  }
  else if ( is_kernel_vaddr(p-(sizeof(void *)+1) ) ) {
    return 1;
  }
  else if ( pagedir_get_page(thread_current ()->pagedir,p) == NULL ) {
    return 1;
  }
  else {
    return 0;
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
  printf("syscall_no: %d\n",syscall_no);
  esp += word_size;
  
  if ( syscall_no == SYS_HALT ) {
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
