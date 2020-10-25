#include "rw_lock.h"

#include <stdio.h>

#include "threads/thread.h"

static bool check_read_acquire_condition(rw_lock_t * rw_lock) {
  return rw_lock->num_writers > 0;
}

static bool check_write_acquire_condition(rw_lock_t * rw_lock) {
  return 
}

static void rw_lock_increment_num_readers(rw_lock_t * rw_lock) {
  struct lock * lock = &rw_lock->lock;
  struct condition * cvar_read = &rw_lock->cvar_read;
  struct condition * cvar_write = &rw_lock->cvar_write;
  
  lock_acquire(lock);
  ASSERT(rw_lock->num_writers >= 0);
  ASSERT(rw_lock->num_readers >= 0);
  while ( rw_lock->num_writers > 0 ) {
    cond_wait(cvar_read, lock);
  }
  // the num_readers lock is held here
  rw_lock->owner = thread_current();
  ++rw_lock->num_readers;
  cond_signal(cvar_write, lock); // wake any writers to prevent starvation
  lock_release(lock);
}

static void rw_lock_increment_num_writers(rw_lock_t * rw_lock) {
  struct lock * lock = &rw_lock->lock;
  struct condition * cvar_read = &rw_lock->cvar_read;
  struct condition * cvar_write = &rw_lock->cvar_write;
  
  lock_acquire(lock);
  ASSERT(rw_lock->num_writers >= 0);
  ASSERT(rw_lock->num_readers >= 0);
  while ( rw_lock->num_readers > 0 || rw_lock->num_writers > 0 ) { // this should be or??
    cond_wait(cvar_write,lock);
  }
  rw_lock->owner = thread_current();
  rw_lock->num_writers += incr; // the num_writers lock is held
  cond_signal(cvar_read, lock); // wake readers to prevent starvation
  lock_release(lock);
}

void rw_lock_init(rw_lock_t * lock) {
  lock->num_readers = 0;
  lock->num_writers = 0;
  lock_init(&lock->lock);
  cond_init(&lock->cvar_read);
  cond_init(&lock->cvar_write);
}

// wait I'm fucking dumb this code is retarded
// how do any test cases pass?

void rw_lock_read_acquire(rw_lock_t * rw_lock) {
  rw_lock_increment_num_readers(rw_lock,1);
}

void rw_lock_read_release(rw_lock_t * rw_lock) {
  rw_lock_increment_num_readers(rw_lock,-1);
}

void rw_lock_write_acquire(rw_lock_t * rw_lock) {
  rw_lock_increment_num_writers(rw_lock,1);
}

void rw_lock_write_release(rw_lock_t * rw_lock) {
  rw_lock_increment_num_writers(rw_lock,-1);
}
