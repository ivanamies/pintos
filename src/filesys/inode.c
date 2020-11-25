#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include <stdio.h>

#include "threads/malloc.h"
#include "threads/rw_lock.h"

#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define NUM_DIRECT_BLOCKS_DISK_MANAGED 10
#define NUM_INDIRECT_BLOCK_DISK_MANAGED 1
#define NUM_DOUBLE_INDIRECT_BLOCK_DISK_MANAGED 1

#define DIRECT_BLOCK_DISK_IDX 0
#define INDIRECT_BLOCK_DISK_IDX (DIRECT_BLOCK_DISK_IDX + NUM_DIRECT_BLOCKS_DISK_MANAGED)
#define DOUBLE_INDIRECT_BLOCK_DISK_IDX (INDIRECT_BLOCK_DISK_IDX + NUM_INDIRECT_BLOCK_DISK_MANAGED)

#define DIRECT_BLOCK_DISK_MAX_MANAGED_LENGTH 8

#define MAX_RECORDKEEPING_BLOCKS (NUM_DIRECT_BLOCKS_DISK_MANAGED + NUM_INDIRECT_BLOCK_DISK_MANAGED + NUM_DOUBLE_INDIRECT_BLOCK_DISK_MANAGED)
#define MAX_RECORDKEEPING_BLOCKS_INDIRECT_INODE 127

typedef struct inode_direct_block_disk {
  int32_t start; // should be block_sector_t type
  // should be of type off_t
  int32_t length; // see DIRECT_BLOCK_DISK_MAX_MANAGED_LENGTH
                   // each direct block disk manages 4kb
  int32_t magic;
  uint32_t unused[125]; // assert this adds up to 512 bytes
} inode_direct_block_disk_t;

// each indirect block disk manages 48 kb
// each double indirect block disk manages 576 kb
typedef struct inode_indirect_block_disk {
  // indices to direct or indirect blocks
  int32_t blocks[MAX_RECORDKEEPING_BLOCKS_INDIRECT_INODE]; // should be block_sector_t type
  int32_t magic;
} inode_indirect_block_disk_t;

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
{  
  // DIRECT_BLOCK_DISK_IDX for direct block start index
  // INDIRECT_BLOCK_DISK_IDX for indirect block start index
  // DOUBLE_INDIRECT_BLOCK_DISK_IDX for double indirect block start index
  int blocks[MAX_RECORDKEEPING_BLOCKS]; // should be block_sector_t type  
  off_t length;                       /* File size in bytes. */
  unsigned magic;                     /* Magic number. */
  int aux;
  uint32_t unused[113];               /* Not used. */
};

// always zeros in pintos bss segment set up
// DO NOT MOVE. MOVING THIS zeros INTO THE FUNCTION CAUSES WEIRD CRASHES
uint8_t zeros[BLOCK_SECTOR_SIZE];
static void inode_direct_block_disk_get(inode_direct_block_disk_t * block, int * sector) {
  const size_t num_sectors = DIRECT_BLOCK_DISK_MAX_MANAGED_LENGTH;
  if ( *sector == -1 ) {
    // allocate sector for the direct block
    ASSERT(sizeof(int) == sizeof(block_sector_t));
    free_map_allocate(1, (block_sector_t *)sector);
    // allocate sectors for the sectors managed by the direct block
    free_map_allocate(num_sectors,(block_sector_t *)&block->start);
    block->length = num_sectors;
    block->magic = INODE_MAGIC;
    cache_block_write(fs_device, *sector, block, 0, BLOCK_SECTOR_SIZE);

    // write zeroes into managed data
    for ( size_t i = 0; i < num_sectors; ++i ) {
      cache_block_write(fs_device, block->start+i, zeros, 0, BLOCK_SECTOR_SIZE);
    }
  }
  else {
    cache_block_read(fs_device, *sector, block, 0, BLOCK_SECTOR_SIZE);    
  }
}

static void inode_indirect_block_disk_get(inode_indirect_block_disk_t * block, int * sector) {
  const size_t managed_blocks = MAX_RECORDKEEPING_BLOCKS_INDIRECT_INODE;
  if ( *sector == -1 ) {
    // allocate sector the indirect block
    ASSERT(sizeof(int) == sizeof(block_sector_t));
    free_map_allocate(1,(block_sector_t *)sector);
    for ( size_t i = 0; i < managed_blocks; ++i ) {
      block->blocks[i] = -1;
    }
    block->magic = INODE_MAGIC;
    
    // the below don't work if the block lives on the stack:
    // cache_block_write(fs_device, 3, block, 0, BLOCK_SECTOR_SIZE);
    // cache_block_read(fs_device, 3, block, 0, BLOCK_SECTOR_SIZE);
    // block_write(fs_device, 3, block);
    // block_read(fs_device, 3, block);
    // it's probably because of a compiler bug corrupting the stack on unwinding
    //
    // this a malloc'd buffer DOES work though
    // it explains why the old code mallocs, operates on, then frees its 512 size blocks
    // like, old "bounce" buffer implementation
    cache_block_write(fs_device, *sector, block, 0, BLOCK_SECTOR_SIZE);
  }
  else {
    cache_block_read(fs_device, *sector, block, 0, BLOCK_SECTOR_SIZE);
  }
}

static void inode_disk_offset_to_block(struct inode_disk * inode_disk, inode_direct_block_disk_t * res, size_t offset) {
  ASSERT(offset <= (8 << 20)); // offset must be less than 8 megabytes

  inode_indirect_block_disk_t * indirect_block = (inode_indirect_block_disk_t *)malloc(sizeof(inode_indirect_block_disk_t));
  memset(indirect_block,0,sizeof(inode_indirect_block_disk_t));
  inode_indirect_block_disk_t * double_indirect_block = (inode_indirect_block_disk_t *)malloc(sizeof(inode_indirect_block_disk_t));
  memset(double_indirect_block,0,sizeof(inode_indirect_block_disk_t));
  int old_sector;
  
  // offset / ( 8 * 512 )
  // want which direct block this offset points to
  int idx = offset / ( DIRECT_BLOCK_DISK_MAX_MANAGED_LENGTH * BLOCK_SECTOR_SIZE);
  if ( idx < INDIRECT_BLOCK_DISK_IDX ) {
    int sector_to_direct_block = inode_disk->blocks[idx];
    inode_direct_block_disk_get(res,&sector_to_direct_block);
    ASSERT(sector_to_direct_block != -1);
    inode_disk->blocks[idx] = sector_to_direct_block;

    // cleanup
    free(indirect_block);
    free(double_indirect_block);
    return;
  }
  
  // go into indirect blocks
  idx -= INDIRECT_BLOCK_DISK_IDX;
  // number of direct blocks managed per indirect inode, 127
  const int blocks_managed1 = MAX_RECORDKEEPING_BLOCKS_INDIRECT_INODE;
  // total number of blocks managed by ALL indirect inodes, 1 * 127
  const int max_blocks_managed1 = NUM_INDIRECT_BLOCK_DISK_MANAGED * blocks_managed1;
  if (idx < max_blocks_managed1 ) {    
    // idx / 127 + 10 == 10
    int indirect_block_idx = idx / blocks_managed1 + INDIRECT_BLOCK_DISK_IDX;
    ASSERT(indirect_block_idx == 10);
    // get indirect block in blocks[10];
    int sector_to_indirect_block = inode_disk->blocks[indirect_block_idx];
    inode_indirect_block_disk_get(indirect_block,&sector_to_indirect_block);
    ASSERT(sector_to_indirect_block != -1);
    inode_disk->blocks[indirect_block_idx] = sector_to_indirect_block;
        
    // idx % 127 to get which direct block inside indirect_block
    const int direct_block_idx = idx % blocks_managed1;
    int sector_to_direct_block = indirect_block->blocks[direct_block_idx];
    old_sector = sector_to_direct_block;
    inode_direct_block_disk_get(res,&sector_to_direct_block);
    ASSERT(sector_to_direct_block != -1);
    // this doesn't need to be written every time
    if ( old_sector != sector_to_direct_block ) {
      indirect_block->blocks[direct_block_idx] = sector_to_direct_block;
      cache_block_write(fs_device, sector_to_indirect_block, indirect_block, 0, BLOCK_SECTOR_SIZE);
    }
    
    // cleanup
    free(indirect_block);
    free(double_indirect_block);
    return;
  }
  
  // go into double indirect blocks
  idx -= max_blocks_managed1;
  // number of blocks managed per double indirect node, 127 x 127 
  const int blocks_managed2 = blocks_managed1 * MAX_RECORDKEEPING_BLOCKS_INDIRECT_INODE;
  // number of blocks managed by ALL double indirect nodes, 1 x 127 x 127
  const int max_blocks_managed2 = NUM_DOUBLE_INDIRECT_BLOCK_DISK_MANAGED * blocks_managed2;
  ASSERT( idx < max_blocks_managed2); // you have no choice here

  // idx / (127 * 127) + 11 == 11
  int double_indirect_block_idx = idx / blocks_managed2 + DOUBLE_INDIRECT_BLOCK_DISK_IDX;
  ASSERT(double_indirect_block_idx == 11);
  int sector_to_double_indirect_block = inode_disk->blocks[double_indirect_block_idx];
  inode_indirect_block_disk_get(double_indirect_block,&sector_to_double_indirect_block);
  inode_disk->blocks[double_indirect_block_idx] = sector_to_double_indirect_block;

  // idx % (127 * 127). There's only one double indirect block but pretend there's more
  idx %= blocks_managed2;
  // idx / 127. Find which indirect block to go to in the doubly indirect block
  const int indirect_block_idx = idx / blocks_managed1;
  int sector_to_indirect_block = double_indirect_block->blocks[indirect_block_idx];
  old_sector = sector_to_indirect_block;
  inode_indirect_block_disk_get(indirect_block,&sector_to_indirect_block);
  if ( old_sector != sector_to_indirect_block ) {
    // write changed double indirect node back to disk
    double_indirect_block->blocks[indirect_block_idx] = sector_to_indirect_block;
    cache_block_write(fs_device, sector_to_double_indirect_block, double_indirect_block, 0, BLOCK_SECTOR_SIZE);
  }

  // idx % 127 to find which direct block to go to
  const int direct_block_idx = idx % blocks_managed1;
  int sector_to_direct_block = indirect_block->blocks[direct_block_idx];
  old_sector = sector_to_direct_block;
  inode_direct_block_disk_get(res,&sector_to_direct_block);
  if ( old_sector != sector_to_direct_block ) {
    // write changed indirect node back to disk
    indirect_block->blocks[direct_block_idx] = sector_to_direct_block;
    cache_block_write(fs_device, sector_to_indirect_block, indirect_block, 0, BLOCK_SECTOR_SIZE);
  }

  // cleanup
  free(indirect_block);
  free(double_indirect_block);
  return;
}

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    rw_lock_t rw_lock;
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
  };

static void inode_extend(struct inode * inode, off_t end);
static void inode_disk_extend(struct inode_disk * disk_inode, size_t length, off_t end);
static off_t inode_length_no_lock (struct inode *inode);

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (struct inode *inode, off_t pos)
{
  if (pos >= (8 << 20)) {
    return -1; // if pos is over 8 mb, give up
  }

  inode_direct_block_disk_t * direct_block = (inode_direct_block_disk_t *)malloc(sizeof(inode_direct_block_disk_t));
  memset(direct_block,0,sizeof(inode_direct_block_disk_t));
  inode_disk_offset_to_block(&inode->data,direct_block,pos);
  // pos %= (8 * 512), each direct block manages 4096
  pos %= (DIRECT_BLOCK_DISK_MAX_MANAGED_LENGTH * BLOCK_SECTOR_SIZE);
  // pos /= 512, find which block inside the managed 4096 to go to
  pos /= BLOCK_SECTOR_SIZE;
  ASSERT ( pos < direct_block->length );
  
  const size_t sector = direct_block->start;
  const block_sector_t res = sector + pos;
  
  free(direct_block);
  return res;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, int aux)
{
  bool success = false;
  
  ASSERT (length >= 0);
  
  // If this assertion fails, the inode structure is not exactly
  //     one sector in size, and you should fix that.
  ASSERT(sizeof(struct inode_disk) == BLOCK_SECTOR_SIZE);
  ASSERT(sizeof(inode_direct_block_disk_t) == BLOCK_SECTOR_SIZE);
  ASSERT(sizeof(inode_indirect_block_disk_t) == BLOCK_SECTOR_SIZE);
  
  struct inode_disk disk_inode;
  memset(&disk_inode,0,sizeof(struct inode_disk));
  for ( size_t i = 0; i < MAX_RECORDKEEPING_BLOCKS; ++i ) {
    disk_inode.blocks[i] = -1;
  }
  disk_inode.length = length;
  disk_inode.aux = aux;
  disk_inode.magic = INODE_MAGIC;
  // have to extend the disk inode
  inode_disk_extend(&disk_inode,0,length);
  cache_block_write(fs_device, sector, &disk_inode, 0, BLOCK_SECTOR_SIZE);
  success = true;
  
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  rw_lock_init(&inode->rw_lock);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->removed = false;
  inode->deny_write_cnt = 0;
  cache_block_read (fs_device, inode->sector, &inode->data, 0, BLOCK_SECTOR_SIZE);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL) {
    rw_lock_write_acquire(&inode->rw_lock);
    inode->open_cnt++;
    rw_lock_write_release(&inode->rw_lock);
  }
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (struct inode *inode)
{
  rw_lock_write_acquire(&inode->rw_lock);
  block_sector_t res = inode->sector;
  rw_lock_write_release(&inode->rw_lock);
  return res;
}

static void write_zeroes_to_disk(block_sector_t sector) {
  void * zeroes = malloc(BLOCK_SECTOR_SIZE);
  memset(zeroes,0,BLOCK_SECTOR_SIZE);
  cache_block_write(fs_device, sector, zeroes, 0, BLOCK_SECTOR_SIZE);
  free(zeroes);  
}

static void inode_direct_block_disk_dealloc(inode_direct_block_disk_t * direct_block) {
  block_sector_t sector = direct_block->start;
  size_t length = direct_block->length;
  for ( size_t i = 0; i < length; ++i ) {
    write_zeroes_to_disk(sector+i);
  }
  free_map_release(sector, length);
  memset(direct_block,0,BLOCK_SECTOR_SIZE);
}

static void inode_indirect_block_disk_dealloc(inode_indirect_block_disk_t * indirect_block, bool is_double_indirect) {
  int sector;
  void * block = malloc(BLOCK_SECTOR_SIZE);
  const size_t max_blocks = MAX_RECORDKEEPING_BLOCKS_INDIRECT_INODE;
  for ( size_t i = 0; i < max_blocks; ++i ) {
    sector = indirect_block->blocks[i];
    if (sector != -1 ) {
      cache_block_read(fs_device, sector, block, 0, BLOCK_SECTOR_SIZE);
      if ( is_double_indirect ) {
        inode_indirect_block_disk_dealloc((inode_indirect_block_disk_t *)block,false /*not double indirect*/);
      }
      else {
        inode_direct_block_disk_dealloc((inode_direct_block_disk_t *)block);
      }
      write_zeroes_to_disk(sector);
      free_map_release((block_sector_t)sector,1);
    }
  }
  free(block);
  memset(indirect_block,0,BLOCK_SECTOR_SIZE);
}

static void inode_disk_dealloc(struct inode_disk * disk_inode) {
  void * block = malloc(BLOCK_SECTOR_SIZE);
  const size_t max_blocks = MAX_RECORDKEEPING_BLOCKS;
  const size_t indirect_blocks_start = INDIRECT_BLOCK_DISK_IDX;
  const size_t double_indirect_blocks_start = DOUBLE_INDIRECT_BLOCK_DISK_IDX;
  int sector;
  bool is_double_indirect;
  for ( size_t i = 0; i < max_blocks; ++i ) {
    sector = disk_inode->blocks[i];
    if ( sector != -1 ) {
      cache_block_read(fs_device, sector, block, 0, BLOCK_SECTOR_SIZE);
      if ( i < indirect_blocks_start ) {
        inode_direct_block_disk_dealloc((inode_direct_block_disk_t *)block);
      }
      else {
        is_double_indirect = i >= double_indirect_blocks_start;
        inode_indirect_block_disk_dealloc((inode_indirect_block_disk_t *)block,is_double_indirect);
      }
      write_zeroes_to_disk(sector);
      free_map_release((block_sector_t)sector,1);
    }
  }
  free(block);
}

static void inode_dealloc(struct inode * inode) {
  inode_disk_dealloc(&inode->data);
  write_zeroes_to_disk(inode->sector);
  free_map_release(inode->sector,1);
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  rw_lock_write_acquire(&inode->rw_lock);
  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      //
      // ... where is the lock that's needed here?
      //
      list_remove (&inode->elem);
      //
      
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          inode_dealloc(inode);
        }
      rw_lock_write_release(&inode->rw_lock);
      free (inode); 
    }
  else {
    rw_lock_write_release(&inode->rw_lock);
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  rw_lock_write_acquire(&inode->rw_lock);
  inode->removed = true;
  rw_lock_write_release(&inode->rw_lock);
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{  
  rw_lock_read_acquire(&inode->rw_lock);
  uint8_t *buffer = (uint8_t *)buffer_;
  off_t bytes_read = 0;
  
  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length_no_lock (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0) {
        break;
      }
      
      cache_block_read (fs_device, sector_idx, buffer + bytes_read, sector_ofs, chunk_size);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  rw_lock_read_release(&inode->rw_lock);

  return bytes_read;
}

static void inode_touch_direct_block(struct inode_disk * disk_inode, off_t target) {
  // inode_disk_offset_to_block does all the memory management
  inode_direct_block_disk_t * direct_block = (inode_direct_block_disk_t *)malloc(sizeof(inode_direct_block_disk_t));
  inode_disk_offset_to_block(disk_inode,direct_block,target);
  
  // it has to be properly initialized
  ASSERT(direct_block->magic == INODE_MAGIC);
  ASSERT(direct_block->length == DIRECT_BLOCK_DISK_MAX_MANAGED_LENGTH);
  // actually this is already zero'd for you
  
  free(direct_block);
}

static void inode_disk_extend(struct inode_disk * disk_inode, size_t curr_length, off_t end) {
  if ( end == 0 ) {
    return;
  }
  
  // 0, make none
  // 1-512, make 1
  // 0-1024, make 2
  if ( curr_length == 0 ) {
    // initialize it
    inode_touch_direct_block(disk_inode,1);
    curr_length = 1;
  }
  int curr_block_length = (curr_length-1) / BLOCK_SECTOR_SIZE;
  int desired_block_length = (end-1) / BLOCK_SECTOR_SIZE;
  while ( curr_block_length <= desired_block_length ) {
    inode_touch_direct_block(disk_inode,(curr_block_length)*BLOCK_SECTOR_SIZE);
    ++curr_block_length;
  }
  disk_inode->length = end;
}

static void inode_extend(struct inode * inode, off_t end) {
  inode_disk_extend(&inode->data, inode_length_no_lock(inode), end);
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at(struct inode *inode, void *buffer_, off_t size,
               off_t offset) 
{  
  const uint8_t *buffer = (const uint8_t *)buffer_;
  off_t bytes_written = 0;

  rw_lock_write_acquire(&inode->rw_lock);
  if (inode->deny_write_cnt) {
    rw_lock_write_release(&inode->rw_lock);
    return 0;
  }
  
  const off_t max_size = 8 << 20; // 8 MB
  const off_t clamped_size = offset + size < max_size ? offset + size : max_size;
  
  if ( inode_length_no_lock(inode) < clamped_size ) {
    inode_extend(inode, clamped_size);
  }
  
  while (size > 0) {    
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector (inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;
        
    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length_no_lock (inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;
    
    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0) {
      break;
    }

    cache_block_write (fs_device, sector_idx, (void *)(buffer + bytes_written), sector_ofs, chunk_size);
    
    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }

  rw_lock_write_release(&inode->rw_lock);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  rw_lock_write_acquire(&inode->rw_lock);
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  rw_lock_write_release(&inode->rw_lock);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  rw_lock_write_acquire(&inode->rw_lock);
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
  rw_lock_write_release(&inode->rw_lock);
}

static off_t
inode_length_no_lock (struct inode *inode)
{
  off_t res = inode->data.length;
  return res;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (struct inode *inode)
{
  rw_lock_read_acquire(&inode->rw_lock);
  off_t res = inode->data.length;
  rw_lock_read_release(&inode->rw_lock);
  return res;
}

int inode_get_sector(struct inode * inode) {
  ASSERT(inode != NULL);
  return inode->sector;
}

int inode_get_aux(struct inode * inode) {
  return inode->data.aux;
}
