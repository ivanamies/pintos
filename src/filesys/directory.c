#include "filesys/directory.h"

#include <stdio.h>
#include <string.h>
#include <list.h>

#include "threads/thread.h"
#include "threads/malloc.h"

#include "filesys/free-map.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"

/* A directory. */
struct dir 
  {
    struct inode *inode;                /* Backing store. */
    off_t pos;                          /* Current position. */
    block_sector_t prev_dir;
  };

/* A single directory entry. */
struct dir_entry 
  {
    block_sector_t inode_sector;        /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
  };

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (block_sector_t sector, size_t entry_cnt, int prev_dir_inode)
{
  int is_dir = 1;
  return inode_create (sector, entry_cnt * sizeof (struct dir_entry), prev_dir_inode, is_dir);
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) 
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL)
    {
      dir->inode = inode;
      dir->pos = 0;
      dir->prev_dir = inode_get_aux1(inode);
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL; 
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) 
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) 
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) 
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp) 
{
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (e.in_use && !strcmp (name, e.name)) 
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode) 
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if (lookup (dir, name, &e, NULL))
    *inode = inode_open (e.inode_sector);
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

 done:
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) 
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e) 
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) 
    {
      dir->pos += sizeof e;
      if (e.in_use)
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        } 
    }
  return false;
}

tokenization_t tokenize_dir_name(const char * name) {
  tokenization_t tokens = { 0 };
  
  if ( name[0] == '/' ) {
    tokens.is_absolute_path = 1;
  }
  // asume null terminated
  const uint32_t name_len = strlen(name)+1;
  char * name_copy = (char *)malloc(name_len);
  strlcpy(name_copy,name,name_len);
  
  char * token = NULL;
  char * save_ptr = NULL;
  
  for ( token = strtok_r(name_copy, "/", &save_ptr); token != NULL;
        token = strtok_r(NULL, "/", &save_ptr) ) {
    if ( tokens.num_names >= DIR_MAX_NAMES ||
         strlen(token) >= DIR_MAX_SUBNAME ) {
      tokens.error = 1;
      break;
    }
    strlcpy(tokens.names[tokens.num_names],token,strlen(token)+1);
    ++tokens.num_names;
  }
  free(name_copy);
  return tokens;
}

static void print_tokenization(tokenization_t * tokens) {
  printf("=====\n");
  printf("tokens %p\n",tokens);
  printf("num names %u\n",tokens->num_names);
  for ( uint32_t i = 0; i < tokens->num_names; ++i ) {
    printf("tokens[%u]: %s\n",i,tokens->names[i]);
  }
}

// to test
// /
// //
// /thing
// /thing/
// ../
// ../thing
// ../curr_dir/curr_file // this should break actually
// /thing/../other
// /thing/../thing
// .
// ../.
// assume everything is a dir
// NULL if fail
struct dir * dir_get(tokenization_t * tokens) {
  struct dir * dir = thread_get_cwd();
  if ( tokens->is_absolute_path ) {
    dir = dir_open_root();
  }
  uint32_t num_names = tokens->num_names;
  struct inode * inode;
  for ( uint32_t i = 0; i < num_names; ++i ) {
    if (strcmp(tokens->names[i],".") == 0 ) { // not interesting
      continue;
    }
    else if (strcmp(tokens->names[i],"..") == 0) {
      block_sector_t prev_sector = dir->prev_dir;
      inode = inode_open(prev_sector);
      if ( i > 0  ) { // do not close the cwd we enter with
        dir_close(dir); // you may close the tmp dirs we opened, i > 0
      }
      dir = dir_open(inode);
    }
    else {
      /* printf("===========\n"); */
      /* printf("tokens->names[i] %s\n",tokens->names[i]); */
      bool success = dir_lookup(dir,tokens->names[i],&inode);
      if ( success ) {
        if ( i > 0  ) { // do not close the cwd we enter with
          dir_close(dir); // you may close the tmp dirs we opened, i > 0
        }
        dir = dir_open(inode);
      }
      else {
        if ( i > 0  ) { // do not close the cwd we enter with
          dir_close(dir); // you may close the tmp dirs we opened, i > 0
        }
        return NULL;
      }
    }
  }
  return dir;
}

bool dir_chdir(const char * name) {
  tokenization_t tokens = tokenize_dir_name(name);
  if ( tokens.error == 1 ) {
    return false;
  }
  struct dir * dir = dir_get(&tokens);
  if ( dir == NULL ) {
    return false;
  }
  else {
    thread_set_cwd(dir);
    return true;
  }
}

bool dir_mkdir(const char * name) {
  if ( strcmp(name,"") == 0 ) {
    return false;
  }
  else if ( strcmp(name,"/") == 0 ) {
    return false;
  }
  tokenization_t tokens = tokenize_dir_name(name);
  if ( tokens.error == 1) {
    return false;
  }
  int num_names = tokens.num_names;
  tokens.num_names--;
  struct dir * dir = dir_get(&tokens);
  struct inode * inode;
  if ( dir != NULL ) {
    bool success = dir_lookup(dir,tokens.names[num_names-1],&inode);
    if ( success ) { // fail if we find the dir in the current dir
      return false;
    }
    block_sector_t sector = 0;
    free_map_allocate(1,&sector);
    ASSERT(sector != 0);
    /* printf("===tagiamies mkdir name %s sector %u\n",tokens.names[num_names-1],sector); */
    const uint32_t some_sector_size = 16;
    block_sector_t prev_sector = inode_get_aux1(dir->inode);
    success = dir_create(sector,some_sector_size,prev_sector);
    ASSERT(success);
    success = dir_add(dir,tokens.names[num_names-1],sector);
    // close any intermediate folders
    // notice how this breaks on:
    // ../cur_folder/cur_file
    // replace with a check if should close function later
    if ( num_names != 1 ) {
      dir_close(dir);
    }
    if ( success ) {
      return true;
    }
    else {
      free_map_release(sector,1);
      return false;
    }
  }
  else {
    return false;
  }
}

int dir_inumber(struct dir * dir) {
  ASSERT(dir != NULL);
  return inode_get_sector(dir_get_inode(dir));
}
