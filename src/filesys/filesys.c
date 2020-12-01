#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>

#include "threads/synch.h"
#include "threads/thread.h"

#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  cache_write_all_entries();
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (struct dir * dir, const char *name, off_t initial_size) 
{
  ASSERT(dir != NULL);
    
  block_sector_t inode_sector = 0;
  int aux1 = dir_inumber(dir);
  int aux2 = 0;
  bool success1 = dir != NULL;
  printf("===ta fc 1\n");
  bool success2 = success1 && free_map_allocate (1, &inode_sector);
  printf("===ta fc 2\n");
  bool success3 = success2 && inode_create (inode_sector, initial_size, aux1, aux2);
  printf("===ta fc 3\n");
  bool success4 = success3 && dir_add (dir, name, inode_sector);
  printf("===ta fc 4\n");

  if (!success4 && inode_sector != 0) {
    free_map_release (inode_sector, 1);
  }
  
  return success4;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (struct dir * dir, const char *name)
{
  ASSERT(dir != NULL);
  struct inode *inode = NULL;
  /* printf("===ta filesys open 1\n"); */
  if (dir != NULL) {
    dir_lookup (dir, name, &inode);
  }
  /* printf("===ta filesys open 2\n"); */
  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (struct dir * dir, const char *name) 
{
  ASSERT(dir != NULL);
  bool success = dir != NULL && dir_remove (dir, name);
  
  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  
  int prev_dir_inode = ROOT_DIR_SECTOR;
  if ( thread_get_cwd() != NULL ) {
    prev_dir_inode = dir_inumber(thread_get_cwd());
  }

  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16, prev_dir_inode))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}

bool filesys_isdir(struct dir * dir, const char * name, struct inode **inode_in) {
  ASSERT(dir != NULL);

  // for whatever reason, I cannot just pass in inode_in...
  // I HAVE to do the *inode_in = inode garbage.
  // this is like weird maybe(?) compiler bug #3(?) on this project.
  // perhaps this is really stack corruption?
  struct inode * inode;
  dir_lookup (dir, name, &inode);

  if ( inode != NULL ) {
    *inode_in = inode;
    return inode_is_dir(inode);
  }
  else {
    return false;
  }
}

