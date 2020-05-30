#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

typedef enum process_status {
  PROCESS_SUCCESSFUL_EXIT,
  PROCESS_UNSUCCESSFUL_EXIT,
  PROCESS_KILLED,
  PROCESS_RUNNING,
  PROCESS_SUCCESSFUL_WAIT_QUERY,
  PROCESS_UNDEFINED,
  PROCESS_STATUS_COUNT
} process_status_e;

void init_process_table(void);
void add_parent_process(int pid);
void remove_parent_process(int pid, process_status_e status);
void add_child_process(int parent_pid, int child_pid, process_status_e child_status);
void set_child_process_status(int parent_pid, int child_pid, process_status_e child_status );
process_status_e get_child_process_status(int parent_pid, int child_pid);

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
