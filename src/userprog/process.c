#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"

#define INPUT_ARGS_MAX_ARGS 60
#define INPUT_ARGS_MAX_ARG_LENGTH 64

#define MAX_PROCESSES 128
#define MAX_CHILD_PROCESSES 128

struct process_info {
  int pid;
  int current_execution_status; // whether the process is running, exited, killed, etc.
  // PROCESS_SUCCESSFUL_EXIT, PROCESS_UNSUCCESSFUL_EXIT, PROCESS_KILLED, enums in .h
  int exit_value; // -1, 0, 2, 3
  int was_queried;
};

// a table of processes to child proceses
// the first entry is parent pid
// the subsequent entries are child pids
static struct lock process_table_lock;
static int num_processes;
static struct process_info ** process_table;

// must acquire lock before calling
static int get_parent_idx_by_pid(int pid) {
  int i;
  for ( i = 0; i < MAX_PROCESSES; ++i ) {
    if ( process_table[i][0].pid == pid ) {
      return i;
    }
  }
  return -1;
}

// must acquire lock before calling
static int get_child_idx_by_pid(int parent_pid_idx, int pid) {
  ASSERT(parent_pid_idx < MAX_PROCESSES);
  int i;
  for ( i = 0; i < MAX_CHILD_PROCESSES; ++i ) {
    if ( process_table[parent_pid_idx][i].pid == pid ) {
      return i;
    }
  }
  return -1;
}

void init_process_table(void) {
  lock_init(&process_table_lock);
  int i, j;
  num_processes = 0;

  // allocate pages for pointers
  int num_bytes_for_ptrs = MAX_PROCESSES * sizeof(struct process_info *);
  int num_pages_for_ptrs = num_bytes_for_ptrs / PGSIZE;
  if (num_pages_for_ptrs == 0 || num_pages_for_ptrs % PGSIZE != 0 ) {
    ++num_pages_for_ptrs;
  }
  /* struct process_info ** p1 = palloc_get_multiple(num_pages_for_ptrs,PAL_ZERO); */
  struct process_info ** p1 = get_pages_from_stack_allocator(0,num_pages_for_ptrs);
  ASSERT ( p1 != NULL );
  int num_bytes_per_row = MAX_CHILD_PROCESSES * sizeof(struct process_info);
  int num_pages_per_row = num_bytes_per_row / PGSIZE;
  if ( num_pages_per_row == 0 || num_pages_per_row % PGSIZE != 0 ) {
    ++num_pages_per_row;
  }
  for ( int i = 0; i < MAX_PROCESSES; ++i ) {
    /* struct process_info * p2 = palloc_get_multiple(num_pages_per_row,PAL_ZERO); */
    struct process_info * p2 = get_pages_from_stack_allocator(0,num_pages_per_row);    
    ASSERT( p2 != NULL);
    p1[i] = p2;
  }  
  
  process_table = p1;
  
  for ( i = 0; i < MAX_PROCESSES; ++i ) {
    for ( j = 0; j < MAX_CHILD_PROCESSES; ++j ) {
      process_table[i][j].pid = -1;
      process_table[i][j].current_execution_status = PROCESS_UNDEFINED;
      process_table[i][j].exit_value = 0;
      process_table[i][j].was_queried = 0;
    }
  }

}

void add_parent_process(int pid) {
  lock_acquire(&process_table_lock);
  ASSERT(num_processes < MAX_PROCESSES);
  int i;
  for ( i = 0; i < MAX_PROCESSES; ++i ) {
    // if we 've seen this process before, do nothing
    if ( process_table[i][0].pid == pid ) {
      break;
    }
    else if ( process_table[i][0].pid == -1  ) {
      process_table[i][0].pid = pid;
      process_table[i][0].current_execution_status = PROCESS_RUNNING;
      break;
    }
  }
  ASSERT(i < MAX_PROCESSES);
  ++num_processes;
  lock_release(&process_table_lock);
}

void remove_parent_process(int pid, int current_execution_status, int exit_value) {
  lock_acquire(&process_table_lock);
  int parent_pid_idx = get_parent_idx_by_pid(pid);
  ASSERT(0 <= parent_pid_idx && parent_pid_idx < MAX_PROCESSES);
  process_table[parent_pid_idx][0].current_execution_status = current_execution_status;
  process_table[parent_pid_idx][0].exit_value = exit_value;
  // never remove the parent pids
  // process_table[parent_pid_idx][0].pid = -1;
  // --num_processes;
  lock_release(&process_table_lock);
}

void add_child_process(int parent_pid, int child_pid) {
  lock_acquire(&process_table_lock);
  int i;
  int parent_pid_idx = get_parent_idx_by_pid(parent_pid);
  ASSERT(0 <= parent_pid_idx && parent_pid_idx < MAX_PROCESSES);
  // find parent_pid table entry
  for ( i = 0; i < MAX_CHILD_PROCESSES; ++i ) {
    if ( process_table[parent_pid_idx][i].pid == -1 ) {
      process_table[parent_pid_idx][i].pid = child_pid;
      process_table[parent_pid_idx][i].current_execution_status = PROCESS_RUNNING;
      break;
    }
  }
  ASSERT ( i != MAX_CHILD_PROCESSES );
  lock_release(&process_table_lock);
}

void set_child_process_status(int parent_pid, int child_pid, int current_execution_status, int exit_value ) {
  lock_acquire(&process_table_lock);
  int parent_pid_idx = get_parent_idx_by_pid(parent_pid);
  ASSERT(0 <= parent_pid_idx && parent_pid_idx < MAX_PROCESSES);
  int child_pid_idx = get_child_idx_by_pid(parent_pid_idx, child_pid);
  ASSERT(0 <= child_pid_idx && child_pid_idx < MAX_CHILD_PROCESSES);
  process_table[parent_pid_idx][child_pid_idx].current_execution_status = current_execution_status;
  process_table[parent_pid_idx][child_pid_idx].exit_value = exit_value;
  lock_release(&process_table_lock);
}

void get_child_process_status(int parent_pid, int child_pid, int * current_execution_status, int * exit_value) {
  lock_acquire(&process_table_lock);
  int parent_pid_idx = get_parent_idx_by_pid(parent_pid);
  ASSERT(0 <= parent_pid_idx && parent_pid_idx < MAX_PROCESSES);
  int child_pid_idx = get_child_idx_by_pid(parent_pid_idx,child_pid);
  ASSERT(0 <= child_pid_idx && child_pid_idx < MAX_CHILD_PROCESSES);
  *current_execution_status = process_table[parent_pid_idx][child_pid_idx].current_execution_status;
  *exit_value = process_table[parent_pid_idx][child_pid_idx].exit_value;
  lock_release(&process_table_lock);
}

static void set_child_process_queried(int parent_pid, int child_pid, int queried) {
  lock_acquire(&process_table_lock);
  int parent_pid_idx = get_parent_idx_by_pid(parent_pid);
  ASSERT(0 <= parent_pid_idx && parent_pid_idx < MAX_PROCESSES);
  int child_pid_idx = get_child_idx_by_pid(parent_pid_idx, child_pid);
  ASSERT(0 <= child_pid_idx && child_pid_idx < MAX_CHILD_PROCESSES);
  process_table[parent_pid_idx][child_pid_idx].was_queried = queried;
  lock_release(&process_table_lock);
}

static int get_child_process_queried(int parent_pid, int child_pid) {
  lock_acquire(&process_table_lock);
  int parent_pid_idx = get_parent_idx_by_pid(parent_pid);
  ASSERT(0 <= parent_pid_idx && parent_pid_idx < MAX_PROCESSES);
  int child_pid_idx = get_child_idx_by_pid(parent_pid_idx, child_pid);
  ASSERT(0 <= child_pid_idx && child_pid_idx < MAX_CHILD_PROCESSES);
  int ret = process_table[parent_pid_idx][child_pid_idx].was_queried;
  lock_release(&process_table_lock);
  return ret;
}

struct input_args {
  pid_t parent_pid;
  
  // signals that the process finished, either successfully or not
  struct lock lk;
  struct condition cv;
  int signal; // -1 for not initialized, 0 for fail, 1 for success
  
  int argc;
  char argv[INPUT_ARGS_MAX_ARGS][INPUT_ARGS_MAX_ARG_LENGTH];

};

static thread_func start_process NO_RETURN;
static bool load (struct input_args * ia, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *input) 
{
  struct input_args* ia;
  char *input_copy;
  char *token, *save_ptr;
  tid_t tid;

  ASSERT(sizeof(struct input_args) <= PGSIZE);
      
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  /* input_copy = palloc_get_page (PAL_ZERO); */
  input_copy = get_pages_from_stack_allocator(0,1);
  
  if (input_copy == NULL)
    return TID_ERROR;
  strlcpy (input_copy, input, PGSIZE);
  
  /* ia = palloc_get_page (0); */
  ia = get_pages_from_stack_allocator(0,1);
  ASSERT(sizeof(ia) <= PGSIZE);
  if ( ia == NULL ) {
    return TID_ERROR;
  }
  memset(ia,0,PGSIZE);
  ia->parent_pid = thread_pid();
  add_parent_process(thread_pid());
  lock_init(&ia->lk);
  cond_init(&ia->cv);
         
  for (token = strtok_r (input_copy, " ", &save_ptr); token != NULL;
       token = strtok_r (NULL, " ", &save_ptr)) {
    ASSERT (ia->argc < INPUT_ARGS_MAX_ARGS);
    ASSERT (strlen(token) < INPUT_ARGS_MAX_ARG_LENGTH);
    strlcpy (ia->argv[ia->argc],token,INPUT_ARGS_MAX_ARG_LENGTH);
    ++ia->argc;
  }
  
  /* Create a new thread to execute FILE_NAME. */
  ia->signal = -1; 
  tid = thread_create (input, PRI_DEFAULT, start_process, ia); // shouldn't this be input_copy?
  // wait until the process was created successfully or not
  lock_acquire(&ia->lk);
  while ( ia->signal == -1 ) {
    cond_wait(&ia->cv,&ia->lk);
  }
  lock_release(&ia->lk);

  if ( ia->signal == 0 ) { // failed to make process
    tid = TID_ERROR;
  }
    
  // free allocated page
  /* palloc_free_page (ia); */
  free_pages_from_stack_allocator(0,ia);
  
  if (tid == TID_ERROR) {
    /* palloc_free_page (input_copy); */
    free_pages_from_stack_allocator(0,ia);
  }

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *input_args_)
{
  struct input_args *ia = input_args_;
  ASSERT(ia != NULL);
  ASSERT(ia->argc != 0);
  struct intr_frame if_;
  bool success;
  
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (ia, &if_.eip, &if_.esp);
  
  /* If load failed, quit. */
  if (!success) 
    thread_exit ();
  
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   1. it was terminated by the kernel (i.e. killed due to an
   exception), returns -1 immediately
   2. If TID is invalid, return -1 immediatly
   3. if it was not a child of the calling process, return -1 immediatly
   4. if process_wait() has already been successfully called for the given TID, returns -1
   immediately

   immediately means "do not wait"
   
   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
  // if child_tid was not spawned by this pid, return -1
  int pid = thread_pid();
  int child_pid_idx = get_child_idx_by_pid(get_parent_idx_by_pid(pid),child_tid);
  if ( child_pid_idx == -1 ) {
    return -1;
  }
  // if we already queried this child pid, return -1
  if ( get_child_process_queried(pid,child_tid) == 1 ) {
    return -1;
  }
  // yield until the child status is not RUNNING
  int current_execution_status;
  int exit_value;
  do {
    get_child_process_status(pid,child_tid,&current_execution_status,&exit_value);
    if ( current_execution_status == PROCESS_RUNNING ) {
      thread_yield();
    }
  } while ( current_execution_status == PROCESS_RUNNING );
  
  // returns -1 if this process has been killed or has been the product of a successful
  // wait query
  if ( current_execution_status == PROCESS_KILLED ) {
    return -1;
  }
  else {
    set_child_process_queried(pid,child_tid,1);
    return exit_value;
  }
}

void process_terminate (int current_execution_status, int exit_code) {
  printf("%s: exit(%d)\n",thread_current()->process_name,exit_code);
  struct thread * cur = thread_current();
  set_child_process_status(cur->parent_pid,thread_pid(),current_execution_status,exit_code);
  // destroy the file descriptors I own that aren't closed
  // will also destroy the executable file descriptor
  //
  // This technically races because now another file can modify
  // this process's executable before process_exit is called but whatever
  /* printf("process terminate 1\n"); */
  destroy_fd(thread_pid());
  /* printf("process terminate 2\n"); */
  thread_exit ();  
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);
    
  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static void* push_stack(void * data, size_t n, void * esp_);
static bool setup_stack (struct input_args * ia, void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (struct input_args * ia, void (**eip) (void), void **esp) 
{
  ASSERT (ia != NULL);
  ASSERT (ia->argc >= 1);
  const char * file_name = ia->argv[0];
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  
  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  strlcpy(t->process_name,file_name,PROCESS_NAME_MAX_LENGTH);
  
  // WIP set working directory to root
  // should be inheriting its cwd from parent
  //
  thread_set_cwd(dir_open_root());
  //
  //
  
  if (t->pagedir == NULL) {
    goto done;
  }
  process_activate ();

  /* Open executable file. */
  struct dir * dir = thread_get_cwd();
  file = filesys_open (dir, file_name);
  
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (ia, esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;
  
  if ( success ) {
    t->parent_pid = ia->parent_pid;
    add_parent_process(thread_pid());
    add_child_process(ia->parent_pid,thread_pid());
    t->exec_fd = open_fd(file_name);
    ASSERT (t->exec_fd >= 2);
    deny_write_fd(t->exec_fd);
  }
 done:  
  // signal to the creating thread that process start up finished
  lock_acquire(&ia->lk);
  ia->signal = success;
  cond_signal(&ia->cv,&ia->lk);
  lock_release(&ia->lk);

  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

void* push_stack(void * data, size_t n, void * esp_) {
  char * esp = (char *)esp_; // cast to char* to avoid pointer arithematic outside of 1 byte types
  
  // reserve n rounded to a multiple of word length
  // I assume a word length is sizeof void*
  size_t to_reserve = (n + sizeof(void *)-1) & (0xFFFFFFFF ^ (sizeof(void*)-1));
  
  esp -= to_reserve;
  memcpy(esp,data,n);
  return esp;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (struct input_args * ia, void **esp) 
{
  
  ASSERT (ia != NULL);
  ASSERT (ia->argc >= 1); // the first argument in ia->argv is the file name 
  uint8_t *kpage;
  int i;
  bool success = false;
  const void * nothing = NULL;
  
  int num_strings_pushed = 0;
  void * strings_on_stack[INPUT_ARGS_MAX_ARGS];
  memset(&strings_on_stack,0,INPUT_ARGS_MAX_ARGS*sizeof(void *));
  
  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success) {
        *esp = PHYS_BASE;
        // set up process stack
        //
        // push on arguments
        for ( i = ia->argc-1; i >= 0; --i ) {
          (*esp) = push_stack(ia->argv[i],strlen(ia->argv[i])+1 /* include null */, *esp);
          strings_on_stack[num_strings_pushed] = *esp;
          ++num_strings_pushed;
        }
        // esp is always rounded to a word length
        // push on nullptr for argv[argc]
        (*esp) = push_stack(&nothing,sizeof(void *),*esp);
        // push on the other string pointers in the order
        // we pushed them on
        for ( i = 0; i < num_strings_pushed; ++i ) {
          (*esp) = push_stack(&strings_on_stack[i],sizeof(void *),*esp);
        }
        // push on the &argv[0] that lives on stack
        (*esp) = push_stack(&(*esp),sizeof(void *),*esp);
        // push on argc
        (*esp) = push_stack(&ia->argc,sizeof(int),*esp);
        // push on dummy return address
        (*esp) = push_stack(&nothing,sizeof(void *),*esp);        
      }
      else {
        palloc_free_page (kpage);
      }
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
