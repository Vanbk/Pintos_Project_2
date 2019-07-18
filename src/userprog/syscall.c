#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/off_t.h"
#include "threads/synch.h"


struct file
  {
    struct inode *inode;        /* File's inode. */
    off_t pos;                  /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
  };


//synchronization method of read and write. 
//but lock only open, write, and read.
struct lock filesys_lock;

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  // filesys_lock synchronization method of read and write. 
  // lock only open, write, and read.
	lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	//printf("syscall : %d\n", *(uint32_t *)(f->esp));
  //hex_dump(f->esp, f->esp, 1000, 1); 
  int system_call_number = *(uint32_t *)(f->esp);
	switch (system_call_number) 
	{
	    case SYS_HALT:
	      break;

	    case SYS_EXIT:
	    	check_user_vaddr(f->esp + 4);
	    	exit(*(uint32_t *)(f->esp + 4));
	      break;

	    case SYS_EXEC:
	    	check_user_vaddr(f->esp + 4);
	    	f->eax = exec((const char *)*(uint32_t *)(f->esp + 4));
	      break;

	    case SYS_WAIT:
	    	f->eax = wait((pid_t)*(uint32_t *)(f->esp + 4));
	      break;

	    case SYS_CREATE:
	    	check_user_vaddr(f->esp + 4);
      	check_user_vaddr(f->esp + 8);
     		f->eax = create((const char *)*(uint32_t *)(f->esp + 4), (unsigned)*(uint32_t *)(f->esp + 8));
	      break;

	    case SYS_REMOVE:
	    	check_user_vaddr(f->esp + 4);
      	f->eax = remove((const char*)*(uint32_t *)(f->esp + 4));
	     	break;

	    case SYS_OPEN:
	    	check_user_vaddr(f->esp + 4);
      	f->eax = open((const char*)*(uint32_t *)(f->esp + 4));
	      break;

	    case SYS_FILESIZE:
	    	check_user_vaddr(f->esp + 4);
      	f->eax = filesize((int)*(uint32_t *)(f->esp + 4));
	      break;

	    case SYS_READ:
	    	check_user_vaddr(f->esp + 4);
      	check_user_vaddr(f->esp + 8);
      	check_user_vaddr(f->esp + 12);
     		f->eax = read((int)*(uint32_t *)(f->esp+ 4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*((uint32_t *)(f->esp + 12)));
	      break;

	    case SYS_WRITE:
	    	f->eax = write((int)*(uint32_t *)(f->esp+4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*((uint32_t *)(f->esp + 12))); 
	      	break;

	    case SYS_SEEK:
	    	check_user_vaddr(f->esp + 4);
      	check_user_vaddr(f->esp + 8);
      	seek((int)*(uint32_t *)(f->esp + 4), (unsigned)*(uint32_t *)(f->esp + 8));
	      break;

	    case SYS_TELL:
	    	check_user_vaddr(f->esp + 4);
      	f->eax = tell((int)*(uint32_t *)(f->esp + 4));
	      break;

	    case SYS_CLOSE:
	    	check_user_vaddr(f->esp + 4);
      	close((int)*(uint32_t *)(f->esp + 4));
	      break;
  }

}

// Terminates Pintos by calling shutdown_power_off()
void 
halt (void) 
{
  // power off the OS
  shutdown_power_off();
}

/*
Runs the executable whose name is given in cmd line, passing any given arguments,
and returns the new process’s program id (pid). Must return pid -1, which otherwise
should not be a valid pid, if the program cannot load or run for any reason. Thus,
the parent process cannot return from the exec until it knows whether the child
process successfully loaded its executable. => use appropriate synchronization
to ensure this.
*/
pid_t 
exec (const char *cmd_line) 
{
  return process_execute(cmd_line);
}

/*
Waits for a child process pid and retrieves the child’s exit status
If pid is still alive, waits until it terminates. Then, returns the status that pid passed
to exit. If pid did not call exit(), but was terminated by the kernel (e.g. killed due
to an exception), wait(pid) must return -1. It is perfectly legal for a parent process
to wait for child processes that have already terminated by the time the parent calls
wait, but the kernel must still allow the parent to retrieve its child’s exit status, or
learn that the child was terminated by the kernel.
*/
int 
wait (pid_t pid) 
{
  return process_wait(pid);
}

/*
Terminates the current user program, returning status to the kernel. If the process’s
parent waits for it (see below), this is the status that will be returned. Conventionally,
a status of 0 indicates success and nonzero values indicate errors.
*/
void 
exit (int status) 
{
  int i;
  printf("%s: exit(%d)\n", thread_name(), status);
  
  //update the exit_status for current thread
  thread_current() -> exit_status = status;

  //When a process dies, we have to close the file it has opened 
  // because it is not close automatically
  for (i = 3; i < 200; i++) 
  {
      if (thread_current()->fd[i] != NULL) 
      {
          close(i);
      }   
  }  
  thread_exit ();
}

/*
Opens the file called file. Returns a nonnegative integer handle called a “file descriptor”
(fd), or -1 if the file could not be opened.
File descriptors numbered 0 and 1 are reserved for the console:
Each process has an independent set of file descriptors. File descriptors are not
inherited by child processes.
When a single file is opened more than once, whether by a single process or different
processes, each open returns a new file descriptor. Different file descriptors for a single
file are closed independently in separate calls to close and they do not share a file
position.
*/

int 
open (const char *file) 
{
  int i;
  int ret = -1;

  struct file* fp; 
  if (file == NULL) 
  {
      exit(-1);
  }
  check_user_vaddr(file);
  // acquire lock when open file
  lock_acquire(&filesys_lock);

  fp = filesys_open(file); // get file descriptor

  if (fp == NULL) 
  {
      ret = -1; 
  } 
  else 
  {
    for (i = 3; i < 200; i++) 
    {
      if (thread_current()->fd[i] == NULL) 
      {
        if (strcmp(thread_current()->name, file) == 0) 
        {
          // executable of running we should prevent writing to the thread. 
          //The process may not be a problem because it is already loaded into memory, but pintos does not want it. 
          //when open the file to perform a write operation
          //if it matches the thread_name on the open side, it will prevent writing and check it in the write function
          // fix rox-simple
          file_deny_write(fp);
        }   
        thread_current()->fd[i] = fp; 
        ret = i;
        break;
      }   
    }   
  }
  //release lock after open
  lock_release(&filesys_lock);
  return ret; 
}

/*
Reads size bytes from the file open as fd into buffer. Returns the number of bytes
actually read (0 at end of file), or -1 if the file could not be read (due to a condition
other than end of file). Fd 0 reads from the keyboard using input_getc().
*/
int 
read (int fd, void* buffer, unsigned size) 
{
  int i;
  int ret;

  // check if the address of the pointer is correct or not
  check_user_vaddr(buffer);

  // acquire lock for reading
  lock_acquire(&filesys_lock);

  if (fd == 0) 
  {
    for (i = 0; i < size; i ++) 
    {
      if (((char *)buffer)[i] == '\0') 
      {
        break;
      }   
    } 
     ret = i;  
  } 
  else if (fd > 2) 
  {
  	if (thread_current()->fd[fd] == NULL) 
  	{
      exit(-1);
    }
    ret = file_read(thread_current()->fd[fd], buffer, size);
  }
  
  // realease the lock after reading
  lock_release(&filesys_lock);
  return ret;
}


/*
Writes size bytes from buffer to the open file fd. Returns the number of bytes actually
written, which may be less than size if some bytes could not be written.
Writing past end-of-file would normally extend the file, but file growth is not implemented
by the basic file system. The expected behavior is to write as many bytes as
possible up to end-of-file and return the actual number written, or 0 if no bytes could
be written at all.
Fd 1 writes to the console. Your code to write to the console should write all of buffer
in one call to putbuf(), at least as long as size is not bigger than a few hundred
bytes. (It is reasonable to break up larger buffers.) Otherwise, lines of text output
by different processes may end up interleaved on the console, confusing both human
readers and our grading scripts.
*/
int 
write (int fd, const void *buffer, unsigned size) 
{
	int ret = -1;

  // check if the address of buffer is valid
	check_user_vaddr(buffer);

  //acquire lock for writing
	lock_acquire(&filesys_lock);
  
  // if write to the console
  if (fd == 1) 
  {
    putbuf(buffer, size);
    ret = size;
  } 

  // if do not write to the console
  else if (fd > 2)
   {

    if (thread_current()->fd[fd] == NULL) 
    {
      exit(-1);
    }

    // check property of the file and deny_write to file if required
    if (thread_current()->fd[fd]->deny_write) 
    {
      file_deny_write(thread_current()->fd[fd]);
    }

    ret = file_write(thread_current()->fd[fd], buffer, size);
  }
  //realease lock after writing
  lock_release(&filesys_lock);
  return ret;
}

/*
Returns the size, in bytes, of the file open as fd.
*/
int 
filesize (int fd) 
{
  if (thread_current()->fd[fd] == NULL)
  {
      exit(-1);
  }
  return file_length(thread_current()->fd[fd]);
}

/*
Creates a new file called file initially initial size bytes in size. 
Returns true if successful,false otherwise. 
*/
bool 
create (const char *file, unsigned initial_size) 
{
	if (file == NULL) 
	{
      exit(-1);
  }
  	check_user_vaddr(file);
  	return filesys_create(file, initial_size);
}

/*
Deletes the file called file. Returns true if successful, false otherwise. A file may be
removed regardless of whether it is open or closed, and removing an open file does
not close it
*/
bool 
remove (const char *file) 
{
	if (file == NULL) 
	{
      exit(-1);
  }
  check_user_vaddr(file);
  return filesys_remove(file);
}

/*
Returns the position of the next byte to be read or written in open file fd, expressed
in bytes from the beginning of the file.
*/
unsigned 
tell (int fd) 
{
  if (thread_current()->fd[fd] == NULL) 
  {
    exit(-1);
  }
  return file_tell(thread_current()->fd[fd]);
}

/*
Changes the next byte to be read or written in open file fd to position, expressed in
bytes from the beginning of the file. (Thus, a position of 0 is the file’s start.)
A seek past the current end of a file is not an error. A later read obtains 0 bytes,
indicating end of file. A later write extends the file, filling any unwritten gap with
zeros. (However, in Pintos files have a fixed length until project 4 is complete, so
writes past end of file will return an error.) These semantics are implemented in the
file system and do not require any special effort in system call implementation.
*/
void 
seek (int fd, unsigned position) 
{
	if (thread_current()->fd[fd] == NULL) 
	{
    	exit(-1);
  }
  file_seek(thread_current()->fd[fd], position);
}

/*
Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open
file descriptors, as if by calling this function for each one.
*/
void 
close (int fd) 
{
	struct file* fp;
  if (thread_current()->fd[fd] == NULL) 
  {
    exit(-1);
  }

  // assigned the NULL pointer when close file
  // it is neccessary in close-twice test
  fp = thread_current()->fd[fd];
  thread_current()->fd[fd] = NULL;
  return file_close(fp);
}

// this function is to filter the bad address (ex: kernel area memory address)
void check_user_vaddr(const void *vaddr) 
{
  if (!is_user_vaddr(vaddr)) 
  {
    exit(-1);
  }
}