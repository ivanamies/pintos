#include "userprog/exception.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#include "userprog/gdt.h"
#include "userprog/process.h"

#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

#include "filesys/file.h"

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

static size_t max_stack_pages = 32;

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */

  int is_process = thread_is_process();
  
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      if ( is_process ) {
        process_terminate(PROCESS_KILLED,-1);
      }
      else {
        thread_exit ();
      }
      break; // don't reach this...
      
    case SEL_KCSEG:      
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel");
      break; // don't reach this...

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      if ( is_process ) {
        process_terminate(PROCESS_KILLED,-1);
      }
      else {
        thread_exit ();
      }
      break; // don't reach this...
    }
}

// like the one in syscall.c but doesn't check unmapped page
static bool check_user_ptr(void * fault_addr_) {
  uint8_t * fault_addr = fault_addr_;
  if ( fault_addr == NULL ) {
    return false;
  }
  else {
    // check if all word sizes are above kernel space
    const int word_size = sizeof(void *);
    for ( int i = 0; i < word_size; ++i ) {
      bool p = is_kernel_vaddr(fault_addr+i);
      if ( p ) {
        return false;
      }
    }    
  }
  return true;
}

int is_stackish(void* fault_addr) {
  // if its within max_stack_pages of PHYS_BASE, its stackish enough for me
  //
  // we check it's not a kernel vaddr previously
  // we check we don't write below the stack pointer previously
  
  // check fault_addr is a reasonable distance from PHYS_BASE
  off_t diff = PHYS_BASE - fault_addr;
  size_t pages_off = diff / PGSIZE;
  bool p1 = pages_off < max_stack_pages;

  return p1;
}

int is_valid_stack_access(struct intr_frame * f, void * fault_addr_, int write UNUSED ) {
  uint8_t * fault_addr = fault_addr_;
  uint8_t * esp = f->esp;
  // PUSHA can push 4 bytes below, PUSH can do 32 bytes
  // this frankly seems kind of bs but hey its in the spec
  uint8_t * last_valid_addr = (uint8_t *)esp - 32; 
  bool res = true;

  // the spec says you cannot write below the stack pointer
  // the test cases imply you also cannot read below the stack pointer also
  /* if ( write ) { */
    // validate esp
  
    // check esp is a user address
    bool p1 = esp && is_user_vaddr(esp);
    // check esp is a reasonable distance from PHYS_BASE
    off_t esp_diff = ((uint8_t *)PHYS_BASE) - esp;
    size_t esp_pages_off = esp_diff / PGSIZE;
    bool p2 = esp_pages_off < max_stack_pages;
    // if esp is reasonable, compare fault_addr to esp
    if ( p1 && p2 ) {
      if ( fault_addr < last_valid_addr ) {
        res = false; // fault address must not be BELOW esp
      }
    }
  /* } */
  return res;
}

static int grow_stack(void * fault_addr) {
  // allocate and map pages until fault_addr stops faulting
  
  uint8_t * upage = pg_round_down(fault_addr);
  // get if its writable from the supplemental page table
  virtual_page_info_t info = get_vaddr_info(&thread_current()->page_table,upage);
  ASSERT (info.frame == NULL );

  frame_aux_info_t * frame_info = frame_alloc(thread_current(),upage);
  uint8_t * kpage = frame_info->kpage;
    
  memset(kpage,0,PGSIZE); // 0 the stack
  
  const bool writable = true;
  bool success = install_page(upage, kpage, writable);
  if ( success ) {
    // update supplemental page table if everything worked
    info.valid = 1;
    info.owner = thread_current();
    info.home = PAGE_SOURCE_OF_DATA_STACK;
    info.frame = kpage;
    info.writable = writable;
    // printf("upage %p writable %d\n",upage,writable);
    set_vaddr_info(&thread_current()->page_table,upage,&info);
  }
  else {
    frame_dealloc(kpage);
  }
  lock_release(&frame_info->pinning_lock);
  return success;
  
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to project 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
  bool not_present;  /* True: not-present page, false: writing r/o page. */
  bool write;        /* True: access was write, false: access was read. */
  bool user;         /* True: access by user, false: access by kernel. */
  void *fault_addr;  /* Fault address. */

  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

  /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
  intr_enable ();

  printf("thread %p enter exception handler\n",thread_current());
  
  /* Count page faults. */
  page_fault_cnt++;

  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;

  // handle page uninstall requests
  if ( thread_current()->page_table.pagedir ) {
    uninstall_request_push();
  }

  // validate memory
  bool valid = check_user_ptr(fault_addr);

  /* printf("tagiamies valid %d fault_addr %p write %d\n",valid,fault_addr,write); */
    
  if ( !valid ) {
    printf ("Page fault at %p: %s error %s page in %s context.\n",
            fault_addr,
            not_present ? "not present" : "rights violation",
            write ? "writing" : "reading",
            user ? "user" : "kernel");
    kill(f);
  }

  uint8_t * upage = pg_round_down(fault_addr);  
  // get if its writable from the supplemental page table
  virtual_page_info_t info = get_vaddr_info(&thread_current()->page_table,upage);

  printf("info.valid %d thread %p upage %p home %d writable %d\n",info.valid,thread_current(),upage,info.home,info.writable);
  
  if ( info.valid == 1 ) {
    
    // frame_alloc will always succeed
    frame_aux_info_t * frame_info = frame_alloc(thread_current(),upage);
    // printf("thread %p frame alloc exit info.home %d\n",thread_current(),info.home);
    uint8_t *kpage = frame_info->kpage;
    
    bool success = true;
    bool writable = true;
    ASSERT(info.home != PAGE_SOURCE_OF_DATA_SWAP_OUT);
    if ( info.home == PAGE_SOURCE_OF_DATA_ELF ||
         info.home == PAGE_SOURCE_OF_DATA_MMAP ) {
      struct file * file = info.file;
      uint32_t page_read_bytes = info.page_read_bytes;
      uint32_t page_zero_bytes = info.page_zero_bytes;
      uint32_t ofs = info.elf_file_ofs;
      ASSERT(page_read_bytes + page_zero_bytes == PGSIZE);
      writable = info.writable;
      file_seek(file,ofs);
      success = file_read (file, kpage, page_read_bytes) == (int) page_read_bytes;
      /* hex_dump(0,kpage,128,false); */
      if ( !success ) {
        printf("page fault exception elf file read failed\n");
        frame_dealloc(kpage);
        kill(f);
      }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);
    }
    else if ( info.home == PAGE_SOURCE_OF_DATA_SWAP_IN ) {
      // printf("thread %p frame %p gotten from %zu\n",thread_current(),kpage,info.swap_loc);
      swap_get_page(kpage,PGSIZE,info.swap_loc);
      // some chance of a transactional problem to update supplemental page table here
      // do it anyways
      // should be impossible, we both lock the page_table lock AND disable interrupts if
      // some other thread is modifying this thread's page_table
      info.home = PAGE_SOURCE_OF_DATA_SWAP_OUT;
      set_vaddr_info(&thread_current()->page_table,upage,&info);
    }
    
    success = install_page (upage, kpage, writable);
    // printf("thread %p released pinning lk %p\n",thread_current(),&frame_info->pinning_lock);
    lock_release(&frame_info->pinning_lock); // release the lock on the kpage
    if (!success) {
      printf("page fault exception install_page failed\n");
      frame_dealloc(kpage);
      printf("successfully dealloc kpage \n");
      kill(f);
    }
  }
  else if (is_stackish(fault_addr)) {
    bool valid_stack_access = is_valid_stack_access(f,fault_addr,write);
    if ( !valid_stack_access ) {
      kill(f);
    }
    int success = grow_stack(fault_addr);
    if (!success) {
      kill(f);
    }    
  }
  else {
    // info was not valid && address not stackish
    kill(f);
  }  

}
