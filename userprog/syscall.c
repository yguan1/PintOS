#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/directory.h"

struct fd
{
  int fd;
  struct file *open_file;
  struct dir *open_dir;
  struct list_elem file_elem;
};

static void syscall_handler (struct intr_frame *);
static void is_valid_addr (const void *vaddr);
static void is_valid_addr_n(const void *uaddr, unsigned size);
static int syscall_exec(const char *command_line);
static int syscall_create (const char *ufile, unsigned initial_size);
static int syscall_remove (const char *ufile);
static int syscall_open (const char *ufile);
static int syscall_filesize (int fd);
static int syscall_read (int fd, void *buffer, unsigned size);
static int syscall_write (int fd, const void *buffer, unsigned size);
static int syscall_tell (int fd);
static void syscall_seek (int fd, unsigned pos);
static void syscall_close (int fd);
static int syscall_chdir(const char *dir);
static int syscall_mkdir(const char *dir);
static int syscall_readdir(int fd, char *name);
static int syscall_isdir(int fd);
static int syscall_inumber(int fd);
static void get_syscall_args(struct intr_frame *f, int *argv, int argc);
static void fd_init(struct fd *new_fd, struct file *open_file, struct dir *open_dir);
static void fd_close(struct fd *target_fd);
static struct fd *find_fd(int target_fd);

struct lock sys_file_lock;

void
syscall_init (void) 
{
  lock_init(&sys_file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int argv[3];
  int *esp = f->esp;
  
  is_valid_addr((const void *)esp);
  int syscall_num = *esp;
  
  switch (syscall_num)
  {
    case SYS_HALT:
    shutdown_power_off();
    break;

    case SYS_EXIT:
    get_syscall_args(f, &argv[0], 1);
    syscall_exit(argv[0]);
    break;

    case SYS_EXEC:
    get_syscall_args(f, &argv[0], 1);
    f->eax = syscall_exec((const char *)argv[0]);
    break;

    case SYS_WAIT:
    get_syscall_args(f, &argv[0], 1);
    f->eax = process_wait(argv[0]);
    break;

    case SYS_CREATE:
    get_syscall_args(f, &argv[0], 2);
    f->eax = syscall_create((const char *)argv[0], (unsigned)argv[1]);
    break;

    case SYS_REMOVE:
    get_syscall_args(f, &argv[0], 1);
    f->eax = syscall_remove((const char *)argv[0]);
    break;

    case SYS_OPEN:
    get_syscall_args(f, &argv[0], 1);
    f->eax = syscall_open((const char *)argv[0]);
    break;

    case SYS_FILESIZE:
    get_syscall_args(f, &argv[0], 1);
    f->eax = syscall_filesize((int)argv[0]);
    break;

    case SYS_READ:
    get_syscall_args(f, &argv[0], 3);
    f->eax = syscall_read((int)argv[0], (void *)argv[1], (unsigned)argv[2]);
    break;

    case SYS_WRITE:
    get_syscall_args(f, &argv[0], 3);
    f->eax = syscall_write((int)argv[0], (const void *)argv[1], (unsigned)argv[2]);
    break;

    case SYS_SEEK:
    get_syscall_args(f, &argv[0], 2);
    syscall_seek((int)argv[0], (unsigned)argv[1]);
    break;

    case SYS_TELL:
    get_syscall_args(f, &argv[0], 1);
    f->eax = syscall_tell((int)argv[0]);
    break;

    case SYS_CLOSE:
    get_syscall_args(f, &argv[0], 1);
    syscall_close((int)argv[0]);
    break;

    case SYS_CHDIR:
    get_syscall_args(f, &argv[0], 1);
    f->eax = syscall_chdir((const char *)argv[0]);
    break;

    case SYS_MKDIR:
    get_syscall_args(f, &argv[0], 1);
    f->eax = syscall_mkdir((const char *)argv[0]);
    break;

    case SYS_READDIR:
    get_syscall_args(f, &argv[0], 2);
    f->eax = syscall_readdir((int)argv[0], (char *)argv[1]);
    break;

    case SYS_ISDIR:
    get_syscall_args(f, &argv[0], 1);
    f->eax = syscall_isdir((int)argv[0]);
    break;

    case SYS_INUMBER:
    get_syscall_args(f, &argv[0], 1);
    f->eax = syscall_inumber((int)argv[0]);
    break;
  }
}

/* store ARGC number of system call arguments into ARGV */
static void
get_syscall_args(struct intr_frame *f, int *argv, int argc)
{
  int *esp, *addr;

  esp = f->esp;
  for (int i = 0; i < argc; i++)
  {
    addr = esp + (i + 1) * sizeof(char);
    is_valid_addr((const void *)addr);
    argv[i] = *addr;
  }
}

/* check if user memory access is valid */
static void
is_valid_addr(const void *uaddr)
{
  if (uaddr == NULL || uaddr < (void *)0x08048000 || !is_user_vaddr(uaddr))
    syscall_exit(-1);
  void *ptr = pagedir_get_page(thread_current()->pagedir, uaddr);
	if (ptr == NULL)
		syscall_exit(-1);
}

static void
is_valid_addr_n(const void *uaddr, unsigned size)
{
  const uint8_t *ptr = uaddr;
  for (; size > 0; size--, ptr++)   
    is_valid_addr((const void *) ptr);
}

/* exit system call */
void
syscall_exit(int status)
{
  thread_current()->exit_status = status;
	printf("%s: exit(%d)\n", thread_current()->name, thread_current()->exit_status);
  
  sema_up(&thread_current()->child_wait);
  /* close all the file discriptors */
  lock_acquire(&thread_current()->file_lock);
  while (!list_empty (&thread_current()->file_list))
  {
    struct list_elem *e = list_pop_front (&thread_current()->file_list);
    struct fd *cur_fd = list_entry (e, struct fd, file_elem);
    free(cur_fd);
  }
  lock_release(&thread_current()->file_lock);

  if (thread_current()->executable != NULL)
    file_close(thread_current()->executable);
  
  sema_down(&thread_current()->child_exit);
  thread_exit();
}

static int
syscall_exec(const char *command_line)
{
  is_valid_addr(command_line);
  return process_execute((const char *)command_line);
}

/* create system call */
static int
syscall_create(const char *ufile, unsigned initial_size)
{ 
  is_valid_addr(ufile);

  lock_acquire(&sys_file_lock);
  bool ok = filesys_create(ufile, initial_size, FILE_INODE);  
  lock_release(&sys_file_lock);

  return ok;
}

/* remove system call */
static int
syscall_remove(const char *ufile)
{
  is_valid_addr(ufile);

  lock_acquire(&sys_file_lock);
  bool ok = filesys_remove(ufile);  
  lock_release(&sys_file_lock);  

  return ok;
}

static void
fd_init(struct fd *new_fd, struct file *open_file, struct dir *open_dir)
{
  new_fd->open_file = open_file;
  new_fd->open_dir = open_dir;
  new_fd->fd = thread_current()->next_fd;

  lock_acquire(&thread_current()->file_lock);
  thread_current()->next_fd++;
  list_push_front(&thread_current()->file_list, &new_fd->file_elem);
  lock_release(&thread_current()->file_lock);
}

static void
fd_close(struct fd *target_fd)
{
  lock_acquire(&thread_current()->file_lock);
  if (target_fd->open_file)
    file_close(target_fd->open_file);
  if (target_fd->open_dir)
    dir_close(target_fd->open_dir);
  list_remove(&target_fd->file_elem);
  lock_release(&thread_current()->file_lock);

  free(target_fd);
}

static int
syscall_open(const char *ufile)
{
  is_valid_addr(ufile);

  if (!strcmp(ufile, ""))
    return -1;

  lock_acquire(&sys_file_lock);
  struct inode *inode = filesys_open(ufile);
  lock_release(&sys_file_lock);

  if (inode == NULL)
    return -1;

  struct fd* new_fd = malloc(sizeof(struct fd));
  if (new_fd == NULL)
    syscall_exit(-1);
  
  if (inode_get_type(inode) == FILE_INODE) {
    struct file *open_file = file_open(inode);
    fd_init(new_fd, open_file, NULL);
  }
  else {
    struct dir *open_dir = dir_open(inode);
    fd_init(new_fd, NULL, open_dir);
  }
  return new_fd->fd;
}

static struct fd *
find_fd(int target_fd)
{
  struct list_elem *e;

  if (list_empty(&thread_current()->file_list))
    return NULL;

  for (e = list_begin (&thread_current()->file_list); 
        e != list_end (&thread_current()->file_list);
        e = list_next (e))
    {
      struct fd *cur_fd = list_entry (e, struct fd, file_elem);
      if (cur_fd->fd == target_fd)
        return cur_fd;
    }
  return NULL;
}

static int
syscall_filesize(int fd)
{
  lock_acquire(&thread_current()->file_lock);
  struct fd *target_fd = find_fd(fd);
  lock_release(&thread_current()->file_lock);

  if (target_fd == NULL)
  {
    syscall_exit(-1);
    return -1;
  }

  lock_acquire(&sys_file_lock);
  unsigned length = file_length(target_fd->open_file);
  lock_release(&sys_file_lock);
  
  return length;
}

static void
syscall_close(int fd)
{
  lock_acquire(&thread_current()->file_lock);
  struct fd *target_fd = find_fd(fd);
  lock_release(&thread_current()->file_lock);

  if (target_fd == NULL)
    syscall_exit(-1);

  fd_close(target_fd);
}

static int
syscall_read(int fd, void *buffer, unsigned size)
{
  is_valid_addr_n(buffer, size);
  unsigned read_size;

  if (fd == 0)
    read_size = input_getc();
  else
  {
    lock_acquire(&thread_current()->file_lock);
    struct fd *target_fd = find_fd(fd);
    lock_release(&thread_current()->file_lock);

    if (target_fd == NULL)
      return -1;
    lock_acquire(&sys_file_lock);
    read_size = file_read(target_fd->open_file, buffer, size);
    lock_release(&sys_file_lock);
  }
  return read_size;
}

static int
syscall_write(int fd, const void *buffer, unsigned size)
{
  is_valid_addr_n(buffer, size);
  
  if (fd == 1)
  {
    putbuf((const char *)buffer, size);
    return size;
  }
  else
  {
    lock_acquire(&thread_current()->file_lock);
    struct fd *target_fd = find_fd(fd);
    lock_release(&thread_current()->file_lock);

    if (target_fd == NULL || target_fd->open_file == NULL)
      return -1;
    
    lock_acquire(&sys_file_lock);
    int write_size = file_write(target_fd->open_file, buffer, size);
    lock_release(&sys_file_lock);

    return write_size;
  }
}

static void
syscall_seek(int fd, unsigned position)
{
  lock_acquire(&thread_current()->file_lock);
  struct fd *target_fd = find_fd(fd);
  lock_release(&thread_current()->file_lock);

  if (target_fd == NULL)
    syscall_exit(-1);
  
  lock_acquire(&sys_file_lock);
  file_seek(target_fd->open_file, position);
  lock_release(&sys_file_lock);
}

static int
syscall_tell(int fd)
{
  lock_acquire(&thread_current()->file_lock);
  struct fd *target_fd = find_fd(fd);
  lock_release(&thread_current()->file_lock);

  if (target_fd == NULL) syscall_exit(-1);

  lock_acquire(&sys_file_lock);
  unsigned pos = file_tell(target_fd->open_file);
  lock_release(&sys_file_lock);

  return pos;
}

static int 
syscall_chdir(const char *dir) 
{
  is_valid_addr(dir);

  lock_acquire(&sys_file_lock);
  bool ok = filesys_chdir(dir);
  lock_release(&sys_file_lock);

  return ok;
}

static int 
syscall_mkdir(const char *dir)
{
  is_valid_addr(dir);

  lock_acquire(&sys_file_lock);
  bool ok = filesys_create(dir, 0, DIR_INODE);  
  lock_release(&sys_file_lock);

  return ok;
}

static int 
syscall_readdir(int fd, char *name)
{
  is_valid_addr(name);

  lock_acquire(&thread_current()->file_lock);
  struct fd *target_fd = find_fd(fd);
  lock_release(&thread_current()->file_lock);

  if (target_fd == NULL || target_fd->open_dir == NULL) return 0;

  struct dir *dir = target_fd->open_dir;
  return dir_readdir(dir, name);
}

static int 
syscall_isdir(int fd)
{
  lock_acquire(&thread_current()->file_lock);
  struct fd *target_fd = find_fd(fd);
  lock_release(&thread_current()->file_lock);

  if (target_fd == NULL) syscall_exit(-1);

  return target_fd->open_dir != NULL;
}

static int 
syscall_inumber(int fd)
{
  lock_acquire(&thread_current()->file_lock);
  struct fd *target_fd = find_fd(fd);
  lock_release(&thread_current()->file_lock);

  struct inode *inode;

  if (target_fd == NULL) syscall_exit(-1);

  if (target_fd->open_file) 
    inode = file_get_inode(target_fd->open_file);
  else if (target_fd->open_dir)
    inode = dir_get_inode(target_fd->open_dir);
  else syscall_exit(-1);

  return inode_get_inumber(inode);
}