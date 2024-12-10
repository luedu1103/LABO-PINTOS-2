#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "threads/malloc.h"

struct file_descriptor
{
  int fd_num;
  tid_t owner;
  struct file *file_struct;
  struct list_elem elem;
};

struct list open_files;

static void syscall_handler(struct intr_frame *);
static int write(int fd, const void *buffer, unsigned size);
static struct file_descriptor *get_open_file(int fd);
static bool is_valid_ptr(const void *usr_ptr);

static void
syscall_handler (struct intr_frame *f)
{
  int syscall_number = *((int *) f->esp);

  switch (syscall_number)
  {
  case SYS_WRITE:
    f->eax = write(*(int *)(f->esp + 4), (const void *)*(int *)(f->esp + 8), *(unsigned *)(f->esp + 12));
    break;
  default:
    thread_exit();
  }
}

void
syscall_init (void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init(&open_files);
}

static int
write (int fd, const void *buffer, unsigned size)
{
  struct file_descriptor *fd_struct;
  int status = 0;

  if (!is_valid_ptr(buffer))
    thread_exit();

  lock_acquire(&filesys_lock);

  if (fd == STDOUT_FILENO)
  {
    putbuf(buffer, size);
    status = size;
  }
  else
  {
    fd_struct = get_open_file(fd);
    if (fd_struct != NULL)
    {
      status = file_write(fd_struct->file_struct, buffer, size);
    }
    else
    {
      status = -1;
    }
  }

  lock_release(&filesys_lock);
  return status;
}

static struct file_descriptor *get_open_file (int fd)
{
  struct list_elem *e;

  for (e = list_begin(&open_files); e != list_end(&open_files); e = list_next(e))
  {
    struct file_descriptor *fd_struct = list_entry(e, struct file_descriptor, elem);
    if (fd_struct->fd_num == fd)
    {
      return fd_struct;
    }
  }

  return NULL;
}

static bool is_valid_ptr(const void *usr_ptr)
{
  return usr_ptr != NULL && is_user_vaddr(usr_ptr);
}