#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>

#include "devices/shutdown.h"
#include "devices/input.h"

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"

#include "userprog/pagedir.h"
#include "userprog/process.h"

#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

#include <string.h>

static void syscall_handler (struct intr_frame *);
static int check_user_ptr (void * p);

#define MAX_PAGES_IN_FILE 8
#define MAX_FILE_NAME_LEN 64
#define MAX_FILES 2048
#define MAX_ARGS_ON_USER_STACK 4
#define MAX_FD_IDX 410

static void halt(void) {
  int j = 0;
  while ( true ) {
    ++j;
  }
}

static struct dir * get_dir_from_name(const char * full_name, int * needs_close,
                                      char * name);

typedef struct fd_file {
  int fd;
  char name[MAX_FILE_NAME_LEN];
  struct file * file;
  struct dir * dir;
  int inumber;
  int is_open; // 0 if this fd is closed, 1 if this fd is open
  int pid; // pid of owning process
} fd_file_t;

// maintain static table of file descriptors out of laziness
static struct lock fd_table_lock;
/* static fd_file_t* fd_table; */
fd_file_t fd_table[MAX_FILES];
static int empty_fd_idx;

void debug_fd_table(int aux) {
  printf("===tag iamies debug fd table %d\n",aux);
  for ( int i = 0; i < MAX_FILES; ++i ) {
    if ( fd_table[i].name[0] != 0 ) {
      printf("fd_table[%d] filename: %s\n",i,fd_table[i].name);
    }
  }
}

void init_fd_table(void) {
  lock_init(&fd_table_lock);
  int i;
  int num_bytes_fd = MAX_FILES * sizeof(fd_file_t);
  int num_pages_fd = num_bytes_fd / PGSIZE;
  if ( num_pages_fd == 0 || num_pages_fd % PGSIZE != 0 ) {
    ++num_pages_fd;
  }
  /* printf("num_pages_fd: %d\n",num_pages_fd); */
  // this asserts
  /* fd_table = palloc_get_multiple(num_pages_fd,PAL_ASSERT | PAL_ZERO); */
  /* fd_table = get_pages_from_stack_allocator(0,num_pages_fd); */
  /* fd_table = malloc(num_bytes_fd); // apparently malloc can handle this */
  ASSERT (fd_table != NULL);
  for ( i = 0; i < MAX_FILES; ++i ) {
    fd_table[i].fd = -1;
    fd_table[i].name[0] = 0;
    fd_table[i].file = NULL;
    fd_table[i].dir = NULL;
    fd_table[i].inumber = -1;
    fd_table[i].is_open = 0;
    fd_table[i].pid = -1;
  }
  
  // do not use 0, which is stdin
  // do not use 1, which is stdout
  // start at 2 so fd and fd_idx are 1 to 1
  empty_fd_idx = 2;  
}

static void clear_fd(struct fd_file * fd_file) {
  if ( fd_file->file != NULL ) {
    if ( fd_file->is_open == 1 ) {
      printf("fd %d name %s\n",fd_file->fd,fd_file->name);
      print_inode(file_get_inode(fd_file->file));
      file_close(fd_file->file);
    }
    fd_file->file = NULL;
  }
  else if ( fd_file->dir != NULL ) {
    if ( fd_file->is_open == 1 ) {
      dir_close(fd_file->dir);
    }
    fd_file->dir = NULL;
  }
  fd_file->fd = -1;
  fd_file->name[0] = 0;
  fd_file->inumber = -1;
  fd_file->is_open = 0;
  fd_file->pid = -1;
}

void destroy_fd(int pid) {
  lock_acquire(&fd_table_lock);
  
  int i;
  for ( i = 0; i < MAX_FILES; ++i ) {
    if ( fd_table[i].pid == pid ) {
      clear_fd(&fd_table[i]);
    }
  }
  lock_release(&fd_table_lock);
}

static int create_fd_file(const char * name, struct file * file) {
  int fd;
  int fd_idx;

  ASSERT ( name != NULL );
  if ( strcmp(name,"") == 0 ) {
    return -1;
  }
  else if ( strlen(name)+1 >= MAX_FILE_NAME_LEN) {
    return -1;
  }

  ASSERT(file != NULL);
  
  lock_acquire(&fd_table_lock);

  ASSERT ( empty_fd_idx < MAX_FILES );
  fd_idx = empty_fd_idx;
  ++empty_fd_idx;
  
  fd = fd_idx; // must start at 2

  fd_table[fd_idx].fd = fd;
  strlcpy(fd_table[fd_idx].name,name,MAX_FILE_NAME_LEN);
  fd_table[fd_idx].file = file;
  fd_table[fd_idx].dir = NULL;
  fd_table[fd_idx].inumber = file_inumber(file);
  fd_table[fd_idx].is_open = 1; // ONLY call from open_fd
  fd_table[fd_idx].pid = thread_pid();
  
  lock_release(&fd_table_lock);
  
  return fd;
}

static bool check_dir_fd_open(struct dir * dir) {
  int inumber = dir_inumber(dir);
  lock_acquire(&fd_table_lock);
  bool success = false;
  for ( int i = 0; i < MAX_FILES; ++i ) {
    if ( fd_table[i].inumber == inumber && fd_table[i].is_open ) {
      success = true;
      break;
    }
  }
  lock_release(&fd_table_lock);
  return success;
}

static int fd_remove(const char * full_name) {
  if ( strcmp(full_name,"") == 0 ) {
    return 0;
  }
  else if ( strcmp(full_name, "/") == 0 ) {
    return 0;
  }
  else if ( strcmp(full_name, ".") == 0 ) {
    return 0;
  }
  else if ( strcmp(full_name, "..") == 0 ) {
    return 0;
  }
  else {
    const uint32_t name_len = NAME_MAX + 1;
    char * name = (char *)calloc(name_len, 1);
    int base_dir_needs_close = 0;
    bool success = false;
    struct dir * base_dir = get_dir_from_name(full_name,&base_dir_needs_close,name);
    struct dir * dir = NULL;
    if ( base_dir == NULL ) {
      goto fd_remove_cleanup;
    }
    struct inode * inode;
    success = dir_lookup(base_dir,name,&inode);
    if ( !success ) {
      goto fd_remove_cleanup;
    }
    bool is_dir = inode_is_dir(inode);
    if ( is_dir ) {
      dir = dir_open(inode);
      ASSERT(dir);
      // check if removing the current directory
      if ( dir_is_same(dir,thread_get_cwd()) ) {
        success = false;
        goto fd_remove_cleanup;
      }
      // check if removing a directory that has something in it
      else if ( !dir_empty(dir) ) {
        success = false;
        goto fd_remove_cleanup;        
      }
      // check if removing an open directory
      // for some reason this isn't being hit in dir-rm-tree ??
      else if ( check_dir_fd_open(dir) ) {
        success = false;
        goto fd_remove_cleanup;        
      }
      else {
        success = filesys_remove(base_dir,name);
        /* int j = 0; */
        /* while ( j < 3000 ) { */
        /*   ++j; */
        /* } */
        
      }      
    }
    else {
      // try to remove if a file
      success = filesys_remove(base_dir,name);
    }
  fd_remove_cleanup:
    if ( dir ) {
      dir_close(dir);
    }
    if ( base_dir_needs_close ) {
      dir_close(base_dir);
    }
    free(name);
    return success;
  }      
}

static int create_fd_dir(struct dir * dir) {
  int fd;
  int fd_idx;

  ASSERT ( dir != NULL );
  
  lock_acquire(&fd_table_lock);
  
  ASSERT ( empty_fd_idx < MAX_FILES );
  fd_idx = empty_fd_idx;
  ++empty_fd_idx;
  
  fd = fd_idx; // must start at 2

  fd_table[fd_idx].fd = fd;
  strlcpy(fd_table[fd_idx].name,"its a dir",MAX_FILE_NAME_LEN);
  fd_table[fd_idx].file = NULL;
  fd_table[fd_idx].dir = dir;
  fd_table[fd_idx].inumber = dir_inumber(dir);
  fd_table[fd_idx].is_open = 1; // ONLY call from open_fd
  fd_table[fd_idx].pid = thread_pid();
  
  lock_release(&fd_table_lock);
  
  return fd;
}

int open_fd(const char * const full_name) {
  int fd;
  struct dir * dir = NULL;
  if (strcmp(full_name,"/") == 0) {
    dir = dir_open_root();
    fd = create_fd_dir(dir);
    return fd;
  }
  else if (strcmp(full_name,".") == 0){
    dir = dir_reopen(thread_get_cwd());
    fd = create_fd_dir(dir);
    return fd;
  }
  else if (strcmp(full_name,"..") == 0) {
    dir = dir_open_prev_dir(thread_get_cwd());
    fd = create_fd_dir(dir);
    return fd;
  }
  
  // all other cases
  const uint32_t name_len = DIR_MAX_SUBNAME + 1;
  char * name = (char *)malloc(name_len);
  memset(name,0,name_len);
  
  int needs_close = 0;
  struct dir * base_dir = get_dir_from_name(full_name,&needs_close,name);
    if( base_dir == NULL ) {
    fd = -1;
    goto open_fd_done;
  }

  struct file * file = NULL;
  struct inode * inode = NULL;
  bool is_dir = filesys_isdir(base_dir,name,&inode);

  if ( is_dir ) {
    /* printf("base_dir %p sector %u full_name %s name %s\n", */
    /*        base_dir,inode_get_sector(dir_get_inode(dir)),full_name,name); */
    /* printf("is dir %d inode %p inode sector %u\n",is_dir,inode, */
    /*        inode_get_sector(inode)); */
  

    ASSERT(inode);
    dir = dir_open(inode);
    if ( dir == NULL ) {
      fd = -1;
      goto open_fd_done;
    }
  }
  else {
    file = filesys_open(base_dir, name); // I assume this is thread safe?
    if ( file == NULL ) {
      fd = -1;
      goto open_fd_done;
    }
  }

  if ( dir != NULL ) {
    fd = create_fd_dir(dir);
  }
  else if ( file != NULL) {
    fd = create_fd_file(name,file);
  }

 open_fd_done:
  if ( needs_close ) {
    dir_close(base_dir);
  }
  free(name);
  
  return fd;
}

static int fd_to_fd_idx_no_lock(int fd) {
  return fd;
}

static int is_valid_file_fd_entry_no_lock(int fd_idx) {
  if ( fd_idx == 0 || fd_idx == 1 || fd_idx >= empty_fd_idx ) {
    return 0;
  }
  else if ( fd_table[fd_idx].file == NULL ||
            fd_table[fd_idx].is_open == 0 ||
            fd_table[fd_idx].pid != thread_pid() ) {
    return 0;
  }
  ASSERT(fd_table[fd_idx].dir == NULL);
  return 1;
}

static int is_valid_dir_fd_entry_no_lock(int fd_idx) {
  if ( fd_idx == 0 || fd_idx == 1 || fd_idx >= empty_fd_idx ) {
    return 0;
  }
  else if ( fd_table[fd_idx].dir == NULL ||
            fd_table[fd_idx].is_open == 0 ||
            fd_table[fd_idx].pid != thread_pid() ) {
    return 0;
  }
  ASSERT(fd_table[fd_idx].file == NULL);
  return 1;
}

static void close_fd(int fd) {
  lock_acquire(&fd_table_lock);

  int fd_idx = fd_to_fd_idx_no_lock(fd);
  int ret = is_valid_file_fd_entry_no_lock(fd_idx);
  printf("close_fd fd %d name %s\n",fd,fd_table[fd_idx].name);
  if ( ret == 1 ) {
    ASSERT(fd_table[fd_idx].file != NULL);
    file_close(fd_table[fd_idx].file);
    fd_table[fd_idx].fd = -1;
    fd_table[fd_idx].is_open = 0;
  }
  else {
    ret = is_valid_dir_fd_entry_no_lock(fd_idx);
    if ( ret == 1 ) {
      ASSERT(fd_table[fd_idx].dir != NULL);
      dir_close(fd_table[fd_idx].dir);
      fd_table[fd_idx].fd = -1;
      fd_table[fd_idx].is_open = 0;
    }
  }
  
  lock_release(&fd_table_lock);
}

static int read_fd(int fd, void * p, unsigned sz) {
  lock_acquire(&fd_table_lock);
  int fd_idx = fd_to_fd_idx_no_lock(fd);
  int ret = is_valid_file_fd_entry_no_lock(fd_idx);
  if ( ret == 1 ) {
    ASSERT(fd_table[fd_idx].file != NULL);
    ASSERT(fd_table[fd_idx].pid == thread_pid());  
    ret = file_read(fd_table[fd_idx].file,p,sz);
  }
  else {
    ret = -1;
  }
  lock_release(&fd_table_lock);
  return ret;
}

static int filesize_fd(int fd) {
  lock_acquire(&fd_table_lock);
  int fd_idx = fd_to_fd_idx_no_lock(fd);
  int ret = is_valid_file_fd_entry_no_lock(fd_idx);
  if ( ret == 1 ) {
    ASSERT(fd_table[fd_idx].file != NULL);
    ASSERT(fd_table[fd_idx].pid == thread_pid());  
    ret = file_length(fd_table[fd_idx].file);
  }
  lock_release(&fd_table_lock);
  return ret;  
}

static int write_fd(int fd, void * p, unsigned sz) {
  lock_acquire(&fd_table_lock);
  int fd_idx = fd_to_fd_idx_no_lock(fd);
  int ret = is_valid_file_fd_entry_no_lock(fd_idx);
  if ( ret == 1 ) {
    ASSERT(fd_table[fd_idx].file != NULL);
    ASSERT(fd_table[fd_idx].pid == thread_pid());
    ret = file_write(fd_table[fd_idx].file,p,sz);
  }
  else {
    ret = -1;
  }
  lock_release(&fd_table_lock);
  return ret;
}

static void seek_fd(int fd, unsigned pos) {
  lock_acquire(&fd_table_lock);
  int fd_idx = fd_to_fd_idx_no_lock(fd);
  int ret = is_valid_file_fd_entry_no_lock(fd_idx);
  if ( ret == 1 ) {
    ASSERT(fd_table[fd_idx].file != NULL);
    ASSERT(fd_table[fd_idx].pid == thread_pid());
    file_seek(fd_table[fd_idx].file,pos);
  }
  lock_release(&fd_table_lock);
}

static int tell_fd(int fd) {
  lock_acquire(&fd_table_lock);
  int fd_idx = fd_to_fd_idx_no_lock(fd);
  int ret = is_valid_file_fd_entry_no_lock(fd_idx);
  if ( ret == 1 ) {
    ASSERT(fd_table[fd_idx].file != NULL);
    ASSERT(fd_table[fd_idx].pid == thread_pid());
    ret = file_tell(fd_table[fd_idx].file);
  }
  lock_release(&fd_table_lock);
  return ret;
}

void deny_write_fd(int fd) {
  lock_acquire(&fd_table_lock);
  int fd_idx = fd_to_fd_idx_no_lock(fd);
  int ret = is_valid_file_fd_entry_no_lock(fd_idx);
  if ( ret == 1 ) {
    ASSERT(fd_table[fd_idx].file != NULL);
    ASSERT(fd_table[fd_idx].pid == thread_pid());
    file_deny_write(fd_table[fd_idx].file);
  }
  lock_release(&fd_table_lock);
}

static int fd_isdir(int fd);

static int fd_readdir(int fd, char * name) {
  bool is_dir = fd_isdir(fd);
  if ( !is_dir ) {
    return 0;
  }
  lock_acquire(&fd_table_lock);
  int fd_idx = fd_to_fd_idx_no_lock(fd);
  int ret = is_valid_dir_fd_entry_no_lock(fd_idx);
  /* printf("fd readdir\n"); */
  /* printf("ret %d\n",ret); */
  /* printf("fd %d fd_idx %d\n",fd,fd_idx); */
  struct dir * dir;
  if ( ret == 1 ) {
    ASSERT(fd_table[fd_idx].dir != NULL);
    ASSERT(fd_table[fd_idx].pid == thread_pid());
    dir = fd_table[fd_idx].dir;
    /* printf("dir %p sector %u\n",dir,inode_get_sector(dir_get_inode(dir))); */
    ASSERT(dir != NULL);
    ret = dir_readdir(dir, name); // ret is now success or fail
    /* printf("name %s\n",name); */
  }
  lock_release(&fd_table_lock);
  return ret;
}

int fd_isdir(int fd) {
  lock_acquire(&fd_table_lock);
  int fd_idx = fd_to_fd_idx_no_lock(fd);
  int ret = is_valid_dir_fd_entry_no_lock(fd_idx);
  lock_release(&fd_table_lock);
  return ret;
}

static int fd_inumber(int fd) {
  bool is_dir = fd_isdir(fd);
  lock_acquire(&fd_table_lock);
  int fd_idx = fd_to_fd_idx_no_lock(fd);
  int ret = 0;
  if ( is_dir ) {
    ret = is_valid_dir_fd_entry_no_lock(fd_idx);
    if ( ret ) {
      struct dir * dir = fd_table[fd_idx].dir;
      ASSERT(dir != NULL);
      ret = inode_get_sector(dir_get_inode(dir));
    }
    else {
      ret = -1;
    }
  }
  else {
    ret = is_valid_file_fd_entry_no_lock(fd_idx);
    if ( ret ) {
      struct file * file = fd_table[fd_idx].file;
      ASSERT(file != NULL);
      ret = inode_get_sector(file_get_inode(file));
    }
    else {
      ret = -1;
    }
  }
  lock_release(&fd_table_lock);
  ASSERT(ret != 0);
  return ret;
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

struct dir * get_dir_from_name(const char * full_name, int * needs_close,
                               char * name) {
  tokenization_t tokens = tokenize_dir_name(full_name);
  if ( tokens.error == 1 ) {
    return NULL;
  }
  strlcpy(name,tokens.names[tokens.num_names-1],DIR_MAX_SUBNAME);
  if ( tokens.num_names == 1 ) {
    *needs_close = 0;
  }
  else {
    *needs_close = 1;
  }
  tokens.num_names--;
  struct dir * dir = dir_get(&tokens);  
  return dir;
}

static int check_user_ptr (void * p_) {
  const char * p = p_;
  int i;
  int success;
  const int word_size = sizeof(void *);
  if ( p == NULL ) {
    return 1;
  }
  else {
    success = 0;
    
    for ( i = word_size-1; i; --i ) {
      success = is_kernel_vaddr(p+i); // make sure every byte is also in user space
      if ( success ) {
        break;
      }
    }
    
    if ( success ) {
      return success;
    }
    
    for ( i = word_size-1; i; --i ) {
      success = (pagedir_get_page(thread_current ()->pagedir,p+i) == NULL);
      if ( success ) {
        break;
      }
    }
    return success;
  }
}

static int check_user_ptr_with_terminate(void * p) {
  if (check_user_ptr(p)) {
    process_terminate(PROCESS_KILLED,-1);
    return 1;
  }
  else {
    return 0;
  }
}

static int get_num_args(int syscall_no) {
  int num_args;
  if ( syscall_no == SYS_HALT ) {
    num_args = 0;
  }
  else if (syscall_no == SYS_EXIT ) {
    num_args = 1;
  }
  else if ( syscall_no == SYS_EXEC ) {
    num_args = 1;
  }
  else if ( syscall_no == SYS_WAIT ) {
    num_args = 1;
  }
  else if ( syscall_no == SYS_CREATE ) {
    num_args = 2;
  }
  else if ( syscall_no == SYS_REMOVE ) {
    num_args = 1;
  }
  else if ( syscall_no == SYS_OPEN ) {
    num_args = 1;
  }
  else if ( syscall_no == SYS_FILESIZE ) {
    num_args = 1;
  }
  else if ( syscall_no == SYS_READ ) {
    num_args = 3;
  }
  else if ( syscall_no == SYS_WRITE ) {
    num_args = 3;
  }
  else if ( syscall_no == SYS_SEEK ) {
    num_args = 2;
  }
  else if ( syscall_no == SYS_TELL ) {
    num_args = 1;
  }
  else if ( syscall_no == SYS_CLOSE ) {
    num_args = 1;
  }
  else if ( syscall_no == SYS_CHDIR ) {
    num_args = 1;
  }
  else if ( syscall_no == SYS_MKDIR ) {
    num_args = 1;
  }
  else if ( syscall_no == SYS_READDIR ) {
    num_args = 2;
  }
  else if ( syscall_no == SYS_ISDIR ) {
    num_args = 1;
  }
  else if ( syscall_no == SYS_INUMBER ) {
    num_args = 1;
  }
  else {
    ASSERT(false);
    num_args = 0;
  }
  return num_args;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int fd;
  
  int tmp_int;
  char * tmp_char_ptr;

  int success;
  
  int syscall_no;
  int status;
  size_t word_size = sizeof(void *);
  char * esp = f->esp; // user's stack pointer
                       // cast to char * to have 1 byte type
  struct dir * dir = NULL;
  int needs_close = 0;
  const uint32_t name_len = DIR_MAX_SUBNAME + 1;
  char * name = NULL;
  
  // verify that it's a good pointer
  if ( check_user_ptr_with_terminate(esp) ) {
    return;
  }
  
  syscall_no = *((int *)esp);
  esp += word_size;

  int num_args = get_num_args(syscall_no);
  void * user_args[MAX_ARGS_ON_USER_STACK];
  memset(user_args,0,MAX_ARGS_ON_USER_STACK*sizeof(void *));

  // only do this for syscall read and file size for now
  for ( int i = 0; i < num_args; ++i ) {
    if ( check_user_ptr_with_terminate(esp) ) {
      return;
    }
    user_args[i] = *((void **)esp);
    esp += word_size;
  }
  
  if ( syscall_no == SYS_HALT ) {
    shutdown_power_off();
  }
  else if (syscall_no == SYS_EXIT ) {
    status = (int)user_args[0];
    process_terminate(PROCESS_SUCCESSFUL_EXIT,status);
    return;
  }
  else if ( syscall_no == SYS_EXEC ) {
    tmp_char_ptr = (char *)user_args[0];
    if ( check_user_ptr_with_terminate(tmp_char_ptr) ) {
      return;
    }
    tid_t p = process_execute(tmp_char_ptr);
    f->eax = p;
  }
  else if ( syscall_no == SYS_WAIT ) {
    f->eax = process_wait((int)user_args[0]);
  }
  else if ( syscall_no == SYS_CREATE ) {
    tmp_char_ptr = (char *)user_args[0];
    tmp_int = (int)user_args[1];
    
    if ( check_user_ptr_with_terminate((void *)tmp_char_ptr /*file_name*/) ) {
      return;
    }
    else if ( strcmp(tmp_char_ptr,"") == 0 ) {
      success = 0;
    }
    else {
      name = (char *)calloc(name_len, 1);
      dir = get_dir_from_name(tmp_char_ptr,&needs_close,name);
      if ( dir == NULL ) {
        success = 0;
      }
      else {
        success = filesys_create(dir, name,tmp_int);
      
        if ( needs_close ) {
          dir_close(dir);
        }
      }
      free(name);
    }    
    f->eax = success;
  }
  else if ( syscall_no == SYS_REMOVE ) {
    tmp_char_ptr = (char *)user_args[0];    
    if ( check_user_ptr_with_terminate((void *)tmp_char_ptr /*file_name*/) ) {
      return;
    }
    f->eax = fd_remove(tmp_char_ptr);
  }
  else if ( syscall_no == SYS_OPEN ) {
    tmp_char_ptr = (char *)user_args[0];
    if ( check_user_ptr_with_terminate((void *)tmp_char_ptr /*file_name*/) ) {
      return;
    }
    else if ( strcmp(tmp_char_ptr,"") == 0 ) {
      fd = -1;
    }
    else {
      fd = open_fd(tmp_char_ptr);
    }
    f->eax = fd;
  }
  else if ( syscall_no == SYS_FILESIZE ) {
    int fd = (int)user_args[0];
    if ( fd < 0 || fd >= MAX_FILES ) {
      f->eax = 0;
    }
    else {
      f->eax = filesize_fd(fd);
    }
  }
  else if ( syscall_no == SYS_READ ) {
    int fd = (int)user_args[0];
    void * p = user_args[1];
    unsigned sz = (unsigned)user_args[2];
    if ( check_user_ptr_with_terminate(p) ) {
      return;
    }
    if ( fd == 0 ) {
      // read from keyboard
      unsigned num_read = 0;
      char key;
      while ( num_read < sz ) {
        key = input_getc();
        memset(p,key,1);
        ++num_read;
      }
      f->eax = sz;
    }
    else if ( fd < 0 || fd >= MAX_FD_IDX ) {
      f->eax = 0;
    }
    else {
      f->eax = read_fd(fd,p,sz);
    }
  }
  else if ( syscall_no == SYS_WRITE ) {
    int fd = (int)user_args[0];
    void * p = user_args[1];
    unsigned size = (unsigned)user_args[2];
    if ( check_user_ptr_with_terminate(p) ) {
      return;
    }
    if ( fd == 1 ) {
      putbuf(p,size);
    }
    else if ( fd < 0 || fd >= MAX_FD_IDX ) {
      f->eax = 0;
    }
    else {
      f->eax = write_fd(fd,p,size);
    }
  }
  else if ( syscall_no == SYS_SEEK ) {
    int fd = (int)user_args[0];
    unsigned pos = (unsigned)user_args[1];
    if (fd < 0 || fd >= MAX_FILES ) {
      f->eax = 0;
    }
    else {
      seek_fd(fd,pos);
    }
  }
  else if ( syscall_no == SYS_TELL ) {
    int fd = (int)user_args[0];
    if (fd < 0 || fd >= MAX_FILES ) {
      f->eax = 0;
    }
    else {
      f->eax = tell_fd(fd);
    }
  }
  else if ( syscall_no == SYS_CLOSE ) {
    int fd = (int)user_args[0];
    if (fd < 0 || fd >= MAX_FILES ) {
      f->eax = 0;
    }
    else {
      close_fd(fd);
    }
  }
  else if ( syscall_no == SYS_CHDIR ) {
    tmp_char_ptr = (char *)user_args[0];    
    if ( check_user_ptr_with_terminate((void *)tmp_char_ptr /*name*/) ) {
      return;
    }
    f->eax = dir_chdir(tmp_char_ptr);
  }
  else if ( syscall_no == SYS_MKDIR ) {
    tmp_char_ptr = (char *)user_args[0];    
    if ( check_user_ptr_with_terminate((void *)tmp_char_ptr /*name*/) ) {
      return;
    }
    f->eax = dir_mkdir(tmp_char_ptr);
  }
  else if ( syscall_no == SYS_READDIR ) {
    int fd = (int)user_args[0];
    tmp_char_ptr = (char *)user_args[1];
    if ( check_user_ptr_with_terminate((void *)tmp_char_ptr /*name*/) ) {
      return;
    }
    if (fd < 0 || fd >= MAX_FILES ) {
      f->eax = 0;
    }
    else {
      f->eax = fd_readdir(fd,tmp_char_ptr);
    }
  }
  else if ( syscall_no == SYS_ISDIR ) {
    int fd = (int)user_args[0];
    if (fd < 0 || fd >= MAX_FILES ) {
      f->eax = 0;
    }
    else {
      f->eax = fd_isdir(fd);
    }
  }
  else if ( syscall_no == SYS_INUMBER ) {
    int fd = (int)user_args[0];
    if (fd < 0 || fd >= MAX_FILES ) {
      f->eax = 0;
    }
    else {
      f->eax = fd_inumber(fd);
    }
  }
  else {
    printf("didn't get a project 2 sys call\n");
    ASSERT(false);
    process_terminate(PROCESS_KILLED,-1);
  }  
}
