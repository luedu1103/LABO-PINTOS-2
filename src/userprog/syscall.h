#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/thread.h"
#include "filesys/file.h"

extern struct lock filesys_lock;
void syscall_init (void);
bool is_valid_ptr (const void *);

#endif /* userprog/syscall.h */
