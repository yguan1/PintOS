#include "filesys/inode.h"
#include <bitmap.h>
#include <list.h>
#include <debug.h>
#include <round.h>
#include <stdio.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* TA note: Most of the modifications for large files
   will be around inode.h and inode.c */

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define DIRECT_CNT 123
#define INDIRECT_CNT 1
#define DBL_INDIRECT_CNT 1
#define SECTOR_CNT (DIRECT_CNT + INDIRECT_CNT + DBL_INDIRECT_CNT)

#define PTRS_PER_SECTOR ((off_t) (BLOCK_SECTOR_SIZE / sizeof (block_sector_t)))
#define INODE_SPAN ((DIRECT_CNT                                              \
                     + PTRS_PER_SECTOR * INDIRECT_CNT                        \
                     + PTRS_PER_SECTOR * PTRS_PER_SECTOR * DBL_INDIRECT_CNT) \
                    * BLOCK_SECTOR_SIZE)

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    block_sector_t sectors[SECTOR_CNT]; /* Sectors. */
    enum inode_type type;               /* FILE_INODE or DIR_INODE. */
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
  };

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
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    struct lock lock;                   /* Protects the inode. */

    /* Denying writes. */
    struct lock deny_write_lock;        /* Protects members below. */
    struct condition no_writers_cond;   /* Signaled when no writers. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    int writer_cnt;                     /* Number of writers. */
  };

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Controls access to open_inodes list. */
static struct lock open_inodes_lock;

static void deallocate_inode (const struct inode *);

/* Initializes the inode module. */
void
inode_init (void)
{
  list_init (&open_inodes);
  lock_init (&open_inodes_lock);
}

/* Initializes an inode of the given TYPE, writes the new inode
   to sector SECTOR on the file system device, and returns the
   inode thus created.  Returns a null pointer if unsuccessful,
   in which case SECTOR is released in the free map. */
struct inode *
inode_create (block_sector_t sector, enum inode_type type)
{

  // ...
  // directly write to the disk as we won't implement buffer..
  struct inode_disk *disk_inode = NULL;
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);
  disk_inode = calloc(1, sizeof *disk_inode);

  if(disk_inode != NULL){
    disk_inode->type = type;
    disk_inode->length = 0;
    disk_inode->magic = INODE_MAGIC;

    // write to file system device
    block_write(fs_device, sector, disk_inode);
    struct inode *inode = inode_open(sector);
    if(inode == NULL){
      free_map_release(sector);
    }
    free(disk_inode);
    return inode;
  }

  return NULL;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  /* Don't forget to access open_inodes list */
  struct list_elem *e;
  struct inode *inode;

  /* first check whether the inode is already open */
  lock_acquire(&open_inodes_lock);
  for (e= list_begin(&open_inodes); e!= list_end(&open_inodes); e= list_next(e)){
    inode = list_entry (e, struct inode, elem);
    if (inode->sector == sector){
      inode->open_cnt ++;
      lock_release(&open_inodes_lock);
      return inode;
    }
  }

  /* inode is not open yet, allocate memory */
  inode = malloc(sizeof *inode);
  if (inode == NULL){
    lock_release(&open_inodes_lock);
    free(inode);
    return NULL;
  }

  /* Initialize */
  list_push_front(&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->removed = false;
  lock_init(&inode->lock);

  lock_init(&inode->deny_write_lock);
  cond_init(&inode->no_writers_cond);
  inode->deny_write_cnt = 0;

  lock_release(&open_inodes_lock);
  return inode;
  
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    {
      lock_acquire (&open_inodes_lock);
      inode->open_cnt++;
      lock_release (&open_inodes_lock);
    }
  return inode;
}

/* Returns the type of INODE. */
enum inode_type
inode_get_type (const struct inode *inode)
{
  /* Read the inode sector and then return the type */
  struct inode_disk *disk_inode = calloc(1, sizeof *disk_inode);
  block_read(fs_device, inode->sector, disk_inode);
  enum inode_type type = disk_inode->type;
  free(disk_inode);
  return type;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode)
{
  /* check inode->open_cnt
    deallocate inode if condition fulfills */
  if (inode == NULL){
    return;
  }

  lock_acquire(&open_inodes_lock);
  /* Release resources if this is the last opener */
  if(-- inode->open_cnt == 0){
    /* Remove it from the list and release the lock */
    list_remove (&inode->elem);
    lock_release(&open_inodes_lock);
    
    /* Deallocate blocks if moved */
    if (inode->removed){
      deallocate_inode(inode);
    }
    free(inode);
  } else{
    lock_release(&open_inodes_lock);
  }
  
}

/* Deallocates SECTOR and anything it points to recursively.
   LEVEL is 2 if SECTOR is doubly indirect,
   or 1 if SECTOR is indirect,
   or 0 if SECTOR is a data sector. */
static void
deallocate_recursive (block_sector_t sector, int level)
{
  if(level > 0){
    /* indirect SECTOR
      in this sector it is a list of block_sector_t */
    block_sector_t *list_of_sectors = calloc(1, sizeof *list_of_sectors);
    block_read(fs_device, sector, list_of_sectors);

    for (int i =0; i< PTRS_PER_SECTOR; i++){
      block_sector_t sector_num = list_of_sectors[i];
      if (sector_num){
        deallocate_recursive(sector_num, level-1);
      }
    }
    free(list_of_sectors);
  }

  /* if level is 0, just free the corresponding bit in bitmap */
  free_map_release(sector);
}

/* Deallocates the blocks allocated for INODE. */
static void
deallocate_inode (const struct inode *inode)
{
  struct inode_disk *disk_inode = calloc(1, sizeof *disk_inode);
  block_read(fs_device, inode->sector, disk_inode);

  /* free the data blocks  */
  for (int i = 0; i< SECTOR_CNT; i++){
    block_sector_t sector_num = disk_inode->sectors[i];
    if(sector_num){
      /* free the sector by calling deallocate_recursive
        find the level of this sector pointer */
      int level = 0;
      if (i >= DIRECT_CNT) {
        if (i >= DIRECT_CNT + INDIRECT_CNT) {
          level = 2;
        }
        level = 1;
      }
      deallocate_recursive(sector_num, level);
    }
  }
  free(disk_inode);

  /* then free the sector that this inode is in */
  deallocate_recursive(inode->sector, 0);
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode)
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Translates SECTOR_IDX into a sequence of block indexes in
   OFFSETS and sets *OFFSET_CNT to the number of offsets. 
   offset_cnt can be 1 to 3 depending on whether sector_idx 
   points to sectors within DIRECT, INDIRECT, or DBL_INDIRECT ranges.
*/
static void
calculate_indices (off_t sector_idx, size_t offsets[], size_t *offset_cnt)
{
  /* Handle direct blocks. When sector_idx < DIRECT_CNT */
  /* offset_cnt = 1, and offsets[0] = sector_idx */
  if(sector_idx < DIRECT_CNT){
    offsets[0] = sector_idx;
    *offset_cnt = 1;
    return;
  }

  /* Handle indirect blocks. */
  /* offset_cnt = 2, offsets[0] = DIRECT_CNT, offsets[1] ... */
  sector_idx -= DIRECT_CNT;
  if (sector_idx < PTRS_PER_SECTOR* INDIRECT_CNT){
    *offset_cnt = 2;
    offsets[0] = DIRECT_CNT;
    offsets[1] = sector_idx % PTRS_PER_SECTOR; 
    return;
  }

  /* Handle doubly indirect blocks. */
  /* offset_cnt = 3, offsets[0] = DIRECT_CNT + INDIRECT_CNT, offsets[1], offsets[2] ... */
  sector_idx -= PTRS_PER_SECTOR * INDIRECT_CNT;
  if(sector_idx < DBL_INDIRECT_CNT * PTRS_PER_SECTOR * PTRS_PER_SECTOR){
    *offset_cnt = 3;
    offsets[0] = DIRECT_CNT + INDIRECT_CNT;
    offsets[1] = sector_idx / PTRS_PER_SECTOR;
    offsets[2] = sector_idx % PTRS_PER_SECTOR;
    return;
  }
  return;
}

/* Retrieves the data block for the given byte OFFSET in INODE,
   setting *DATA_BLOCK to the block and data_sector to the sector to write 
   (for inode_write_at method).
   Returns true if successful, false on failure.
   If ALLOCATE is false (usually for inode read), then missing blocks 
   will be successful with *DATA_BLOCK set to a null pointer.
   If ALLOCATE is true (for inode write), then missing blocks will be allocated. 
   This method may be called in parallel */
static bool
get_data_block (struct inode *inode, off_t offset, bool allocate,
                void **data_block, block_sector_t *data_sector)
{

  /* calculate_indices ... then access the sectors in the sequence 
   * indicated by calculate_indices 
   * Don't forget to check whether the block is allocated (e.g., direct, indirect, 
   * and double indirect sectors may be zero/unallocated, which needs to be handled
   * based on the bool allocate */

  /* first convert offset to sector_idx and calculate offsets */
  off_t sector_idx = offset / BLOCK_SECTOR_SIZE;
  size_t offsets[3];
  size_t offset_cnt;
  calculate_indices(sector_idx, offsets, &offset_cnt);

  /* now do a looping to get to the data block sector */
  block_sector_t current_sector = inode->sector;
  size_t current_level = 0;
  uint32_t *data = NULL;
  data = malloc(BLOCK_SECTOR_SIZE);
  
  while(current_level < offset_cnt){
    /* read it as uint32_t since block_sector_t is uint32_t
      and hence data points to the array of sectors in disk_inode */   
    block_read(fs_device, current_sector, data);

    /* first check if the block is allocated */
    if(data[offsets[current_level]] != 0){
      current_sector = data[offsets[current_level]];

      if(current_level == (offset_cnt-1)){
        /* we hit the data block
          e.g. indirect block, level should be 1, offset_cnt = 2
          Return the data block */
        block_read(fs_device, current_sector, *data_block);
        *data_sector = current_sector;
        free(data);
        return true;
      }
      
      // else not hit data block yet, go to the next level
      current_level++;
      continue;
    }

    /* otherwise, no block is allocated */
    if(allocate == false){
      /* for inode read, then missing blocks will be successful
        with *data_block set to a null pointer */
      *data_block = NULL;
      free(data);
      return true;
    } else {
      /* for for inode write, then missing blocks will be allocated. 
        This method may be called in parallel */
      
      /* first check again whether someone else might allocated the block
        in the meantime */
      block_read(fs_device, current_sector, data);
      if(data[offsets[current_level]] != 0){
        /* continue to the next while loop with current_level
          and current_sector unchanged, so it will enter the case when
          the block is allocated */
        continue; 
      }else{
        /* allocate the new block */
        bool allocate_success = free_map_allocate(&data[offsets[current_level]]);
        
        if (!allocate_success){
          /* fail to allocate */
          *data_block = NULL;
          free(data);
          return false;
        } else{
          /* allocate successfully
            make the block point to zero data */
          uint8_t zero_data[BLOCK_SECTOR_SIZE];
          memset(zero_data, 0, BLOCK_SECTOR_SIZE);
          block_write(fs_device, data[offsets[current_level]], zero_data);
          block_write(fs_device, current_sector, data);
          /* go around again to follow the new pointer
            without updating current_level and current_sector */
          continue;
        }
      }
    }
  }
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. 
   Some modifications might be needed for this function template. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset)
{
  ASSERT(inode != NULL);

  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  block_sector_t target_sector = 0;
  
  while (size > 0)
    {
      /* Sector to read, starting byte offset within sector, sector data. */
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;
      void *block;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      block = malloc(BLOCK_SECTOR_SIZE);
      
      if (chunk_size <= 0 || !get_data_block (inode, offset, false, &block, &target_sector)){
        free(block);
        break;
      }
      
      if (block == NULL)
        memset (buffer + bytes_read, 0, chunk_size);
      else
        memcpy (buffer + bytes_read, block + sector_ofs, chunk_size);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
      free(block);
    }

  return bytes_read;
}

/* Extends INODE to be at least LENGTH bytes long. */
static void
extend_file (struct inode *inode, off_t length)
{
  struct inode_disk *disk_inode = calloc(1, sizeof *disk_inode);
  block_read(fs_device, inode->sector, disk_inode);
  if (length > disk_inode->length){
    disk_inode->length = length;
    block_write(fs_device, inode->sector, disk_inode);
  }
  free(disk_inode);
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if an error occurs. 
   Some modifications might be needed for this function template.*/
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset)
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  block_sector_t target_sector = 0;
  /* Don't write if writes are denied. */
  lock_acquire (&inode->deny_write_lock);
  if (inode->deny_write_cnt)
    {
      lock_release (&inode->deny_write_lock);
      return 0;
    }
  inode->writer_cnt++;
  lock_release (&inode->deny_write_lock);
  while (size > 0)
    {
      /* Sector to write, starting byte offset within sector, sector data. */
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;
      void *block;

      /* Bytes to max inode size, bytes left in sector, lesser of the two. */
      off_t inode_left = INODE_SPAN - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      
      block = malloc(BLOCK_SECTOR_SIZE);
      if (chunk_size <= 0 || !get_data_block (inode, offset, true, &block, &target_sector)){
        free(block);
        break;
      }
        
      memcpy (block + sector_ofs, buffer + bytes_written, chunk_size);
      block_write(fs_device, target_sector, block);

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
      free(block);
    }
  extend_file (inode, offset);

  lock_acquire (&inode->deny_write_lock);
  if (--inode->writer_cnt == 0)
    cond_signal (&inode->no_writers_cond, &inode->deny_write_lock);
  lock_release (&inode->deny_write_lock);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode)
{
  lock_acquire(&inode->deny_write_lock);
  while(inode->writer_cnt > 0){
    cond_wait(&inode->no_writers_cond, &inode->deny_write_lock);
  }
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  lock_release(&inode->deny_write_lock);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode)
{
  lock_acquire(&inode->deny_write_lock);
  /* check must be called by some inode who has called inode_deny_write() */
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt --;
  lock_release(&inode->deny_write_lock);
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  struct inode_disk *disk_inode = calloc(1, sizeof *disk_inode);
  block_read(fs_device, inode->sector, disk_inode);
  off_t length = disk_inode->length;
  free(disk_inode);
  return length;
}

/* Returns the number of openers. */
int
inode_open_cnt (const struct inode *inode)
{
  int open_cnt;

  lock_acquire (&open_inodes_lock);
  open_cnt = inode->open_cnt;
  lock_release (&open_inodes_lock);

  return open_cnt;
}

/* Locks INODE. */
void
inode_lock (struct inode *inode)
{
  lock_acquire (&inode->lock);
}

/* Releases INODE's lock. */
void
inode_unlock (struct inode *inode)
{
  lock_release (&inode->lock);
}
