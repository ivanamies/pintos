#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

// it will be mutually exclusive with ready_list
// like sema waiters
static struct list sleep_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&sleep_list);
  list_init (&all_list);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{  
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;
  
  /* Add to run queue. */
  thread_unblock (t);
  
  // the thread created here may be higher priority than
  // thread who did the createing.
  thread_yield ();
  
  return tid;
}

void thread_sleep(void) {
  // interrupts are off
  ASSERT (!intr_context ());
  int old_level = intr_disable ();

  // block thread
  list_push_back (&sleep_list, &thread_current()->elem);
  thread_block ();

  // maybe interrupts are on again
  intr_set_level (old_level);
}

void thread_unsleep(void) {
  // inside the interrupt handler so I can't be interrupted
  while (!list_empty (&sleep_list)) {
    thread_unblock (list_entry (list_pop_front (&sleep_list),
                                struct thread, elem));
  }
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);
  list_push_back (&ready_list, &t->elem);
  t->status = THREAD_READY;
  intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable ();
  list_remove (&thread_current()->allelem);
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;
  
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  if (cur != idle_thread) 
    list_push_back (&ready_list, &cur->elem);
  cur->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) 
{
  thread_current ()->priority = new_priority;
  thread_current ()->non_donated_priority = new_priority;
  thread_yield ();
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  return thread_current ()->priority;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED) 
{
  /* Not yet implemented. */
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  /* Not yet implemented. */
  return 0;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
  /* Not yet implemented. */
  return 0;
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
  /* Not yet implemented. */
  return 0;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  enum intr_level old_level;

  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  t->priority = priority;

  // initialize non donated priority
  t->non_donated_priority = priority;
  // initialize semaphores slots
  memset(t->sema_held,0,MAX_SEMAS_HOLD*sizeof(struct sema *));

  t->magic = THREAD_MAGIC;

  old_level = intr_disable ();
  list_push_back (&all_list, &t->allelem);
  intr_set_level (old_level);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

// written assuming interrupts are off
// get the maximum priority from all the threads a
// semaphore has trapped
/* static int */
/* get_max_pri_from_sema(struct list * my_list) */
/* { */
  /* struct list_elem * e; */
  /* struct thread * t; */
  /* static int small = -1; */
  /* int max_pri = small; */
  /* int counter = 0; */
  /* for ( e = list_begin (my_list); e != list_end (my_list); */
  /*       e = list_next (e) ) */
  /* { */
    /* t = list_entry (e, struct thread, elem); */
    /* if ( max_pri < t->priority ) { */
    /*   max_pri = t->priority; */
    /* } */
  /* } */
  /* e = list_begin(my_list); */
  /* e = list_next(e); */
  /* ASSERT (false && "3"); */
  /* return max_pri; */
/* } */

static void
thread_donate_pri(struct thread * me)
{
  static int small = 1;
  int max_pri = small;
  while ( me ) {
    if ( max_pri < me->priority ) {
      max_pri = me->priority;
    }
    me->priority = max_pri;
    me = me->waiting_for;
  }
}

static void
thread_donate_pri_with_aux(struct thread * me, void * aux)
{
  me->aux = aux;
  thread_donate_pri(me);
}

static void
thread_restore_old_pri(struct thread * me, void * aux)
{
  me->aux = aux;
  me->priority = me->non_donated_priority;
}

static void
thread_stop_waiting(struct thread * me, void * aux)
{
  // wait a second I'm not using the doubly linked list provided
  // by the kernel...
  struct thread * to_stop_waiting_on = (struct thread *)(aux);
  while ( me && me->waiting_for ) {
    if ( me->waiting_for == to_stop_waiting_on ) {
      me->waiting_for = me->waiting_for->waiting_for;
    }
    me = me->waiting_for;
  }
}

// written assumign interrupts are off
// gets the maximum priority from all semaphores the thread holds
// less donation more non-optional sharing
static void
thread_request_donate_pri(struct thread * me)
{
  me = NULL;
  ASSERT (me == NULL);
  
  thread_foreach(thread_restore_old_pri,NULL);
  thread_foreach(thread_donate_pri_with_aux,NULL);
}

static void
thread_request_stop_waiting(struct thread * me) {
  thread_foreach(thread_stop_waiting,me);
}

static int
search_non_empty_sema_slot(struct thread * me)
{
  for ( int i = 0; i < MAX_SEMAS_HOLD; ++i )
   {
     if ( !me->sema_held[i] )
     {
       return i;
     }
   }
  ASSERT (false); // thread should always have a slot for new semaphore
  return -1;
}

void
thread_failed_acquire_sema(struct thread * me, struct semaphore * sema)
{
  // do nothing for now
  struct thread * tmp = sema->holding_thread;
  sema->holding_thread = me;
  sema->holding_thread = tmp;
  ///////////////
  
  thread_donate_pri (me);
}

void
thread_failed_acquire_sema_block(struct thread * me, struct semaphore * sema)
{
  me->waiting_for = sema->holding_thread;
  thread_failed_acquire_sema(me,sema);
  list_push_back (&sema->waiters, &me->elem);
  thread_block ();
}

void
thread_acquire_sema(struct thread * me, struct semaphore * sema)
{
  // int slot = search_non_empty_sema_slot(me);
  // me->sema_held[slot] = sema;
  sema->holding_thread = me;
  me->waiting_for = NULL;
  
  thread_request_donate_pri(me);
}
  
void
thread_release_sema(struct thread * me, struct semaphore * sema)
{
  /* // search for semaphore that is being held and release it */
  /* for ( size_t i = 0; i < MAX_SEMAS_HOLD; ++i ) { */
  /*   if ( me->sema_held[i] == sema ) { // must be holding the semaphore and only one copy held */
  // me->sema_held[i] = NULL;
      sema->holding_thread = NULL;
      me->waiting_for = NULL;
      thread_request_stop_waiting(me);
      thread_request_donate_pri(me);
      /* return; */
  /*   } */
  /* } */
  // ASSERT (false); // this should never happen

  /* if ( list_empty (&sema->waiters) ) { */
  /*   me->priority = me->non_donated_priority; */
  /* } */
  
}

struct thread *
pop_highest_pri_thread (struct list * my_list)
{
  // schedules the thread with the highest priority
  struct list_elem * e;
  struct thread * t;
  struct list_elem * my_thread_e = NULL;
  struct thread * my_thread = NULL;
  for ( e = list_begin (my_list); e != list_end (my_list);
        e = list_next (e) )
  {
    t = list_entry (e, struct thread, elem);
    if ( !my_thread || (my_thread && my_thread->priority < t->priority) )
    {
      my_thread = t;
      my_thread_e = e;
    }
  }
  ASSERT (my_thread_e);
  list_remove(my_thread_e);
  return my_thread;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  if (list_empty (&ready_list)) {
    return idle_thread;
  }
  else {
    // schedules the thread with the highest priority
    struct thread * next_thread = pop_highest_pri_thread(&ready_list);
    return next_thread;
  }
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void) 
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

#define DEBUG_LOG

char DEBUG_CHAR_BUFFER[DEBUG_CHAR_BUFFER_LEN];
size_t DEBUG_CHAR_BUFFER_HEAD = 0;

void write_debug(void * stuff, size_t n_bytes) {
#ifdef DEBUG_LOG
  memcpy(&DEBUG_CHAR_BUFFER[DEBUG_CHAR_BUFFER_HEAD],stuff,n_bytes);
  DEBUG_CHAR_BUFFER_HEAD+=n_bytes;
#endif
}
void print_debug() {
#ifdef DEBUG_LOG
  printf("DEBUG_CHAR_BUFFER_HEAD: %zu\n",DEBUG_CHAR_BUFFER_HEAD);
  for ( size_t i = 0; i < DEBUG_CHAR_BUFFER_LEN; ++i ) {
    printf("%c",DEBUG_CHAR_BUFFER[i]);
  }
#endif
}

void write_debug_ptr(void * ptr) {
#ifdef DEBUG_LOG
  write_debug("ptr: 0x",sizeof("ptr: 0x"));
  write_debug((void *)((((size_t)ptr) & 0xF0000000) + '0'),sizeof(char));
  write_debug((void *)((((size_t)ptr) & 0x0F000000) + '0'),sizeof(char));
  write_debug((void *)((((size_t)ptr) & 0x00F00000) + '0'),sizeof(char));
  write_debug((void *)((((size_t)ptr) & 0x000F0000) + '0'),sizeof(char));
  write_debug((void *)((((size_t)ptr) & 0x0000F000) + '0'),sizeof(char));
  write_debug((void *)((((size_t)ptr) & 0x00000F00) + '0'),sizeof(char));
  write_debug((void *)((((size_t)ptr) & 0x000000F0) + '0'),sizeof(char));
  write_debug((void *)((((size_t)ptr) & 0x0000000F) + '0'),sizeof(char));
  write_debug((void *)('\n'),sizeof(char));
#endif
}


/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);
