#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

// not to be confused with exit status
// eg we can have
// process execution status = PROCESS_SUCCESSFUL_EXIT
// exit value = 2
typedef enum process_execution_status {
  PROCESS_SUCCESSFUL_EXIT,
  PROCESS_UNSUCCESSFUL_EXIT,
  PROCESS_KILLED,
  PROCESS_RUNNING,
  PROCESS_UNDEFINED,
  PROCESS_STATUS_COUNT
} process_execution_status_e;

void init_process_table(void);
void add_parent_process(int pid);
void remove_parent_process(int pid, int current_execution_status, int exit_value);
void add_child_process(int parent_pid, int child_pid);
void set_child_process_status(int parent_pid, int child_pid, int current_execution_status, int exit_status);
void get_child_process_status(int parent_pid, int child_pid, int * current_execution_status, int * exit_status);

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
