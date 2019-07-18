#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <lib/stdbool.h>

typedef int pid_t;

void syscall_init (void);

void halt (void) ;
pid_t exec (const char *cmd_line) ;
void exit (int status) ;
int wait (pid_t pid);
int open (const char *file);
int read (int fd, void* buffer, unsigned size) ;
int write (int fd, const void *buffer, unsigned size);
int filesize (int fd);
bool create (const char *file, unsigned initial_size) ;
bool remove (const char *file);
void seek (int fd, unsigned position) ;
unsigned tell (int fd);
void close (int fd);

void check_user_vaddr(const void *vaddr);

#endif /* userprog/syscall.h */
