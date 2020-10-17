#ifndef THREADS_RW_LOCK_H
#define THREADS_RW_LOCK_H

#include "synch.h"

typedef struct rw_lock {
  
  int num_readers;
  int num_writers;
  struct lock lock;
  
  struct condition cvar_read;
  struct condition cvar_write;
  
} rw_lock_t;

void rw_lock_init(rw_lock_t * rw_lock);

void rw_lock_read_acquire(rw_lock_t * rw_lock);

void rw_lock_read_release(rw_lock_t * rw_lock);

void rw_lock_write_acquire(rw_lock_t * rw_lock);

void rw_lock_write_release(rw_lock_t * rw_lock);

#endif // THREADS_RW_LOCK_H
