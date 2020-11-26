#ifndef FILESYS_DIRECTORY_H
#define FILESYS_DIRECTORY_H

#include <stdbool.h>
#include <stddef.h>
#include "devices/block.h"

/* Maximum length of a file name component.
   This is the traditional UNIX maximum length.
   After directories are implemented, this maximum length may be
   retained, but much longer full path names must be allowed. */
#define NAME_MAX 14
#define DIR_MAX_NAMES 16
#define DIR_MAX_SUBNAME NAME_MAX

struct inode;

// tokenize
typedef struct tokenization {
  uint32_t num_names;
  char names[DIR_MAX_NAMES][DIR_MAX_SUBNAME + 1];
  int is_absolute_path;
} tokenization_t;

tokenization_t tokenize_dir_name(const char * name);

/* Opening and closing directories. */
bool dir_create (block_sector_t sector, size_t entry_cnt, int prev_dir_inode);
struct dir *dir_open (struct inode *);
struct dir *dir_open_root (void);
struct dir *dir_reopen (struct dir *);
void dir_close (struct dir *);
struct inode *dir_get_inode (struct dir *);

/* Reading and writing. */
bool dir_lookup (const struct dir *, const char *name, struct inode **);
bool dir_add (struct dir *, const char *name, block_sector_t);
bool dir_remove (struct dir *, const char *name);
bool dir_readdir (struct dir *, char name[NAME_MAX + 1]);

// functions I added
bool dir_chdir(const char * name);
bool dir_mkdir(const char * name);
int dir_inumber(struct dir *);
// obtains the folder associated with tokens
struct dir * dir_get(tokenization_t * tokens);

#endif /* filesys/directory.h */
