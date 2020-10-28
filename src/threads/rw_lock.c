#include "rw_lock.h"

#include <stdio.h>

#include "threads/thread.h"

// duplicate code because generalizing it makes it harder to understand
// the locking sucks already, rolling some weird runtime templating won't add to it

static void rw_lock_increment_num_readers(rw_lock_t * rw_lock) {
  struct lock * lock = &rw_lock->lock;
  struct condition * cvar_read = &rw_lock->cvar_read;
  
  lock_acquire(lock);
  ASSERT(rw_lock->num_writers >= 0);
  ASSERT(rw_lock->num_readers >= 0);
  while ( rw_lock->num_writers > 0 ) {
    cond_wait(cvar_read, lock);
  }
  ASSERT(rw_lock->num_writers == 0); // no writers hold rw_lock
  // the fields lock is held here
  ++rw_lock->num_readers;
  lock_release(lock);
}

static void rw_lock_increment_num_writers(rw_lock_t * rw_lock) {
  struct lock * lock = &rw_lock->lock;
  struct condition * cvar_write = &rw_lock->cvar_write;
  
  lock_acquire(lock);
  ASSERT(rw_lock->num_writers >= 0);
  ASSERT(rw_lock->num_readers >= 0);
  while ( rw_lock->num_readers > 0 || rw_lock->num_writers > 0 ) {
    cond_wait(cvar_write,lock);
  }
  ASSERT(rw_lock->num_readers == 0 && rw_lock->num_writers == 0); // no one holds rw_lock
   // the fields lock is held here
  ++rw_lock->num_writers;
  lock_release(lock);
}

static void rw_lock_decrement_num_readers(rw_lock_t * rw_lock) {
  struct lock * lock = &rw_lock->lock;
  struct condition * cvar_read = &rw_lock->cvar_read;
  struct condition * cvar_write = &rw_lock->cvar_write;
  lock_acquire(lock);
  ASSERT(rw_lock->num_writers == 0); // no writers hold rw_lock
  ASSERT(rw_lock->num_readers > 0); // 1 (myself) or more readers hold rw_lock
  --rw_lock->num_readers;
  cond_signal(cvar_write, lock); // wake writers
  cond_signal(cvar_read, lock); // then wake readers
  lock_release(lock);
}

static void rw_lock_decrement_num_writers(rw_lock_t * rw_lock) {
  struct lock * lock = &rw_lock->lock;
  struct condition * cvar_read = &rw_lock->cvar_read;
  struct condition * cvar_write = &rw_lock->cvar_write;
  lock_acquire(lock);
  ASSERT(rw_lock->num_writers == 1); // 1 (myself) writer holds rw_lock
  ASSERT(rw_lock->num_readers == 0); // no readers hold rw_lock
  --rw_lock->num_writers;
  cond_signal(cvar_read,lock); // wake readers
  cond_signal(cvar_write, lock); // then wake writers
  lock_release(lock);
}

void rw_lock_init(rw_lock_t * lock) {
  lock->num_readers = 0;
  lock->num_writers = 0;
  lock_init(&lock->lock);
  cond_init(&lock->cvar_read);
  cond_init(&lock->cvar_write);
}

void rw_lock_read_acquire(rw_lock_t * rw_lock) {
  rw_lock_increment_num_readers(rw_lock);
}

void rw_lock_read_release(rw_lock_t * rw_lock) {
  rw_lock_decrement_num_readers(rw_lock);
}

void rw_lock_write_acquire(rw_lock_t * rw_lock) {
  rw_lock_increment_num_writers(rw_lock);
}

void rw_lock_write_release(rw_lock_t * rw_lock) {
  rw_lock_decrement_num_writers(rw_lock);
}
