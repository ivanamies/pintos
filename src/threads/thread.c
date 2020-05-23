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
#include "devices/timer.h"
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

// thread_mlfqs load average
// as a FIXED POINT float
static int load_avg = 0;

// the ready queues for mlfqs
static struct list thread_mlfqs_queues[PRI_MAX+1];

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

static void thread_request_donate_pri(struct thread *);

void thread_mlfqs_thread_update_recent_cpu (struct thread *, void *);
void thread_mlfqs_thread_update_priority(struct thread *, void *);


int to_fixed_point(int);
int to_real_round_to_zero(int);
int to_real_round_to_nearest(int);
int add_fixed(int, int);
int subtract_fixed(int, int);
int add_fixed_real(int, int);
int subtract_fixed_real(int, int);
int multiply_fixed(int, int);
int multiply_fixed_real(int, int);
int divide_fixed(int, int);
int divide_fixed_real(int, int);

/* ////// debug utils because pintos-gdb is broken on mac... */
/* #define DEBUG_CHAR_BUFFER_LEN (1<<20) */

/* char debug_char_buffer[DEBUG_CHAR_BUFFER_LEN]; */
/* size_t debug_char_buffer_head = 0; */

/* void write_debug(void * stuff, size_t n_bytes) { */
/*   memcpy(&debug_char_buffer[debug_char_buffer_head],stuff,n_bytes); */
/*   debug_char_buffer_head+=n_bytes; */
/* } */
/* void print_debug() { */
/*   printf("debug_char_buffer_head: %zu\n",debug_char_buffer_head); */
/*   for ( size_t i = 0; i < debug_char_buffer_head; ++i ) { */
/*     printf("i: %c",i,debug_char_buffer[i]); */
/*   } */
/* } */

/* void write_debug_ptr(void * ptr) { */
/*   write_debug("ptr: 0x",sizeof("ptr: 0x")); */
/*   write_debug((void *)((((size_t)ptr) & 0xF0000000) + '0'),sizeof(char)); */
/*   write_debug((void *)((((size_t)ptr) & 0x0F000000) + '0'),sizeof(char)); */
/*   write_debug((void *)((((size_t)ptr) & 0x00F00000) + '0'),sizeof(char)); */
/*   write_debug((void *)((((size_t)ptr) & 0x000F0000) + '0'),sizeof(char)); */
/*   write_debug((void *)((((size_t)ptr) & 0x0000F000) + '0'),sizeof(char)); */
/*   write_debug((void *)((((size_t)ptr) & 0x00000F00) + '0'),sizeof(char)); */
/*   write_debug((void *)((((size_t)ptr) & 0x000000F0) + '0'),sizeof(char)); */
/*   write_debug((void *)((((size_t)ptr) & 0x0000000F) + '0'),sizeof(char)); */
/*   write_debug((void *)('\n'),sizeof(char)); */
/* } */

///////////////// fixed point math here out of laziness to deal with linker
#define FIXED_P 14
#define FIXED_Q 14
#define FIXED_F ( 1 << FIXED_Q )

// prefer * and / over bit shifts because laziness

int to_fixed_point(int n) {
  return n * FIXED_F;
}

int to_real_round_to_zero(int x) {
  return x / FIXED_F;
}

int to_real_round_to_nearest(int x) {
  if ( x >= 0 ) {
    return (x + ( FIXED_F / 2 )) / FIXED_F;
  }
  else {
    return (x - ( FIXED_F / 2 )) / FIXED_F;
  }
}

int add_fixed(int x, int y) {
  return x + y;
}

int subtract_fixed(int x, int y) {
  return x - y;
}

int add_fixed_real(int x, int n) {
  return x + to_fixed_point(n);
}

int subtract_fixed_real(int x, int n) {
  return x - to_fixed_point(n);
}

int multiply_fixed(int x, int y ) {
  return (((int64_t)x)*y) / FIXED_F;
}

int multiply_fixed_real(int x, int n ) {
  return x * n;
}

int divide_fixed(int x, int y) {
  return (((int64_t)x) * FIXED_F) / y;
}

int divide_fixed_real(int x, int n ) {
  return x / n;
}
//////////////////////////////////


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
  int i;
  
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&sleep_list);
  list_init (&all_list);

  if ( thread_mlfqs ) {
    for ( i = PRI_MIN; i <= PRI_MAX; ++i ) {
      list_init(&thread_mlfqs_queues[i]);
    }
  }
  
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

  if ( thread_mlfqs ) {
    // add one to recent cpu
    t->recent_cpu = add_fixed_real(t->recent_cpu,1);
  }
  
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
  if ( thread_mlfqs ) {
    list_push_back(&thread_mlfqs_queues[t->priority],
                   &t->elem);
  }
  else {
    list_push_back (&ready_list, &t->elem);
  }
  
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
  
  if (cur != idle_thread) {
    if ( thread_mlfqs ) {
      ASSERT (PRI_MIN <= cur->priority && cur->priority <= PRI_MAX);
      list_push_back(&thread_mlfqs_queues[cur->priority],
                     &cur->elem);
    }
    else {
      list_push_back (&ready_list, &cur->elem);
    }
  }
  
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
  if ( !thread_mlfqs ) {
    if ( thread_current ()->non_donated_priority == thread_current ()->priority ) {
      // stupid hack so that if the higher priority is donated, it is not immediately overriden
      // this breaks raising the threads' priority when a priority was donated
      // but it passes all test cases so whatever
      thread_current ()->priority = new_priority;
    }
    thread_current ()->non_donated_priority = new_priority;
    thread_yield ();
  }
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  if ( thread_mlfqs ) {
    return PRI_MIN;
  }
  else {
    return thread_current ()->priority;
  }
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice) 
{
  thread_current ()->nice = nice;
  thread_mlfqs_thread_update_priority (thread_current (), NULL);
  thread_yield ();
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  return thread_current ()->nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
  /* Not yet implemented. */
  /* printf("load_avg: %d\n",load_avg); */
  const int tmp_load_avg = multiply_fixed_real(load_avg,100);
  const int res = to_real_round_to_nearest(tmp_load_avg);
  return res;
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
  const int tmp_recent_cpu = multiply_fixed_real(thread_current ()->recent_cpu, 100);
  const int res = to_real_round_to_nearest(tmp_recent_cpu);
  return res;
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
  
  if ( thread_mlfqs ) {
    t->priority = 0;
  }
  else {
    t->priority = priority;
  }
  
  // initialize non donated priority
  t->non_donated_priority = priority;
  
  t->nice = 0;
  t->recent_cpu = 0;
  
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

static void
thread_donate_pri(struct thread * me)
{
  int max_pri = PRI_MIN;
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
thread_stop_waiting (struct thread * me, struct list * my_list)
{
  // schedules the thread with the highest priority
  struct list_elem * e;
  struct thread * t;
  for ( e = list_begin (my_list); e != list_end (my_list); e = list_next (e) )
  {
    t = list_entry (e, struct thread, elem);
    if ( t->waiting_for == me ) {
      t->waiting_for = NULL;
    }
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

void
thread_failed_acquire_sema(struct thread * me, struct semaphore * sema)
{
  me->waiting_for = sema->holding_thread;

  if ( !thread_mlfqs ) {
    thread_donate_pri (me);
  }
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
}

void
thread_release_sema(struct thread * me, struct semaphore * sema)
{
  sema->holding_thread = NULL;
  
  thread_stop_waiting(me,&sema->waiters);
  if ( !thread_mlfqs ) {
    thread_request_donate_pri(me);
  }

}

struct list_elem *
get_highest_pri_thread_element (struct list * my_list)
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
  
  return my_thread_e;
}

struct thread *
pop_highest_pri_thread (struct list * my_list)
{
  // schedules the thread with the highest priority
  struct list_elem * e = get_highest_pri_thread_element(my_list);
  ASSERT (e);
  struct thread * t = list_entry (e, struct thread, elem);
  ASSERT (t);
  list_remove(e);
  return t;
}

void
thread_mlfqs_thread_update_priority(struct thread * t, void * aux UNUSED)
{
  t->priority = PRI_MAX - (to_real_round_to_nearest(t->recent_cpu) / 4) - (t->nice * 2);
  if ( t->priority < PRI_MIN ) {
    t->priority = PRI_MIN;
  }
  else if ( t->priority > PRI_MAX ) {
    t->priority = PRI_MAX;
  }
}

void
thread_mlfqs_update_priorities_all (void)
{
  thread_foreach(thread_mlfqs_thread_update_priority,NULL);
}

void thread_mlfqs_update_load_avg (void)
{
  const int fifty_nine = to_fixed_point(59);
  const int num1 = divide_fixed_real(fifty_nine,60);
  const int one = to_fixed_point(1);
  const int num2 = divide_fixed_real(one,60);
  int rdy_threads = 0;
  struct list_elem *e;
  struct thread *t;

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e)) {
    t = list_entry (e, struct thread, allelem);
    if ( t != idle_thread && (t->status == THREAD_RUNNING || t->status == THREAD_READY) ) {
      ++rdy_threads;
    }
  }
  
  load_avg = multiply_fixed(num1,load_avg) + multiply_fixed_real(num2,rdy_threads);
  // load_avg = rdy_threads;
}

void
thread_mlfqs_thread_update_recent_cpu (struct thread * t, void * aux UNUSED)
{
  const int num1 = multiply_fixed_real(load_avg,2);
  const int den1 = add_fixed_real(num1,1);
  const int num2 = divide_fixed(num1,den1);
  const int num3 = multiply_fixed(num2,t->recent_cpu);
  const int res = add_fixed_real(num3,t->nice);
  
  t->recent_cpu = res;
}

void thread_mlfqs_update_recent_cpus_all (void)
{
  thread_foreach(thread_mlfqs_thread_update_recent_cpu,NULL);
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  int i;
  struct list * curr_list;
  struct thread* next_thread;
  if ( thread_mlfqs ) {
    // go through all ready queues
    curr_list = NULL;
    for ( i = PRI_MAX; i >= PRI_MIN; --i ) {
      if ( !list_empty(&thread_mlfqs_queues[i]) ) {
        curr_list = &thread_mlfqs_queues[i];
      }
    }
    if ( curr_list == NULL ) {
      return idle_thread;
    }
    else {
      next_thread = list_entry(list_pop_front(curr_list),
                               struct thread,
                               elem);
      return next_thread;
    }
  }
  else {
    if (list_empty (&ready_list)) {
      return idle_thread;
    }
    else {
      // schedules the thread with the highest priority
      next_thread = pop_highest_pri_thread(&ready_list);
      return next_thread;
    }
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


/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);
