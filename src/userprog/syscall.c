#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include "threads/synch.h"

static void syscall_handler (struct intr_frame *);

int user_to_kernel_ptr(const void *vaddr);
int process_add_file(struct file *f);
struct file* process_get_file(int fd);
void process_close_file(int fd);
struct lock file_locked;
void check_address(const void *vaddr);
void check_buffer(void* buf, unsigned size);
void get_arg(struct intr_frame *f, int *arg, int n);
struct process_file
{	
	struct file *file;
	int fd;
	struct list_elem elem;
};

void
syscall_init (void) 
{
	lock_init(&file_locked);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
	int arg[4];
	check_address((const void*) f->esp);
	//int esp = user_to_kernel_ptr((const void*) f->esp);
	switch(*(int*)f->esp)//switch(arg[0]) or switch(*(int*)f->esp)
	{
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			get_arg(f, &arg[0], 1);			
			exit(arg[0]);
			//exit(arg[1]);
			break;
		case SYS_EXEC:
			//arg[1] = user_to_kernel_ptr((const void *) arg[1]);
			//f->eax = exec((char *) arg[1]);
			get_arg(f, &arg[0], 1);
			//check_string((const void*)argv[o]);
			f->eax = exec((const char *)arg[0]);
			break;
                case SYS_WRITE:
                        //arg[0] = user_to_kernel_ptr((const void *)arg[0]);
                        get_arg(f, &arg[0], 3);
			check_buffer((void *)arg[1], (unsigned) arg[2]);
			arg[1] = user_to_kernel_ptr((const void *) arg[1]);
			f->eax = write(arg[0], (const void*)arg[1], (unsigned) arg[2]);	
                        break;
		case SYS_WAIT:
			get_arg(f, &arg[0], 1);
			f->eax = wait(arg[0]);
			break;
		case SYS_CREATE:
			get_arg(f, &arg[0], 2);
			arg[0] = user_to_kernel_ptr((const void *) arg[0]);
			f->eax = create(((const char *)arg[0]), (unsigned) arg[1]);
			break;
		case SYS_REMOVE:
			ASSERT(false);
			get_arg(f, &arg[0], 1);
			arg[0] = user_to_kernel_ptr((const void *)arg[0]);
			f->eax = remove((const char *) arg[0]);
			break;
		case SYS_OPEN:	
			get_arg(f, &arg[0], 2);
			arg[0] = user_to_kernel_ptr((const void *)arg[0]);
			f->eax =open((char *) arg[0]);
			break;
		case SYS_FILESIZE:
			get_arg(f, &arg[0], 1);
			f->eax =filesize( arg[0]);
			break;
		case SYS_READ:
			get_arg(f, &arg[0], 3);
			check_buffer((void *)arg[1], (unsigned) arg[2]);
			arg[1] = user_to_kernel_ptr((const void *)arg[1]);
			f->eax =read(arg[0], (void*)arg[1], (unsigned) arg[2]);
			break;
		case SYS_SEEK:
			get_arg(f, &arg[0], 2);
			seek(arg[0], (unsigned) arg[1]);
			break;
		case SYS_TELL:
			get_arg(f, &arg[0], 1);
			f->eax =tell(arg[0]);
			break;
		case SYS_CLOSE:
			get_arg(f, &arg[0], 1);
			close(arg[0]);
			break;
	}
}

int user_to_kernel_ptr(const void *vaddr)
{
	check_address(vaddr);
	void *pointer = pagedir_get_page(thread_current()->pagedir, vaddr);
	if(!pointer)
	{
		exit(-1);
	}
	return (int) pointer;
}
struct file* process_get_file(int file_description)
{
	struct thread *t = thread_current();
	struct list_elem *e;

	for(e = list_begin(&t->file_list); e != list_end(&t->file_list); e = list_next(e))
	{
		struct process_file *pf = list_entry(e, struct process_file, elem);
		if(file_description == pf->fd)
		{return pf->file;}
	}
	return NULL;

}
int process_add_file(struct file *f)
 {
  	struct process_file *pf = malloc(sizeof(struct process_file));
	 pf->file = f;
	pf->fd = thread_current()->fd;
	thread_current()->fd++;
	list_push_back(&thread_current()->file_list, &pf->elem);
	return pf->fd;
 }

void process_close_file(int fd)
{
	struct thread *t = thread_current();
	struct list_elem *next, *e = list_begin(&t->file_list);
	while (e != list_end (&t->file_list))
	 {
		next = list_next(e);
		struct process_file *pf = list_entry (e, struct process_file, elem);
		if (fd == pf->fd || fd == -1)
		{
			file_close(pf->file);
			list_remove(&pf->elem);
			free(pf);
			if (fd != -1)
			{
				return;
			}
		}
		 e = next;
	}
}

void halt(void)
{
	shutdown_power_off();
}

void exit (int status)
{
//	struct thread *t = thread_current();///uncommenting these causes sp-bad-sp & others to fail!
//	t->status = status;
	printf("%s: exit(%d)\n", thread_current()->name, status);
	thread_exit(); 
}
pid_t exec (const char *cmd_line)
{
	pid_t pid = process_execute(cmd_line);
	
	return pid;
}
int open(const char *file)
{
	lock_acquire(&file_locked);
	struct file *f = filesys_open(file);
	if(!f)
	{
		lock_release(&file_locked);
		return -1;
	}
	int file_description = process_add_file(f);
	lock_release(&file_locked);
	return file_description;
}
int write (int file_description, const void *buffer, unsigned size)
{
	if(file_description == STDOUT_FILENO)
	{
		putbuf(buffer, size);
		return size;
	}
	lock_acquire(&file_locked);
	struct file *f = process_get_file(file_description);
	if(!f)
	{
		lock_release(&file_locked);
		return -1;
	}
	int written =  file_write(f, buffer, size);
	lock_release(&file_locked);
	return written;
}

int wait (pid_t pid)
{
	return process_wait(pid);
}
bool create(const char *file, unsigned initial_size)
{
	lock_acquire(&file_locked);
	bool success = filesys_create(file, initial_size);
	lock_release(&file_locked);
	return success;
}
bool remove(const char *file)
{
	lock_acquire(&file_locked);
	bool success = filesys_remove(file);
	lock_release(&file_locked);
	return success;
}
int filesize(int fd)
{
	lock_acquire(&file_locked);
	struct file *f = process_get_file(fd);
	if(!f)
	{
		lock_release(&file_locked);
		return -1;
	}	
	int size = file_length(f);
	lock_release(&file_locked);
	return size;
}
int read(int fd, void *buffer, unsigned size)
{
	if(fd == STDIN_FILENO)
	{
		unsigned i;
		uint8_t* local_buffer = (uint8_t*)buffer;
		
	//	lock_acquire(&file_locked);
		for(i = 0; i < size; i++)
		{
			local_buffer[i] = input_getc();
		}
		return size;	
	//	lock_release(&file_locked);
	}

	lock_acquire(&file_locked);
	struct file *f = process_get_file(fd);
	if(!f)
	{
		lock_release(&file_locked);
		return -1;
	}	
	int reading = file_read(f, buffer, size);
	
	lock_release(&file_locked);
	return reading;
}

void seek (int file_description, unsigned position)
{	
	lock_acquire(&file_locked);
	struct file *f = process_get_file(file_description);
	if(!f)
	{
		lock_release(&file_locked);
		return ;
	}	
	file_seek(f, position);
	
	lock_release(&file_locked);
}
unsigned tell (int file_description)
{	
	lock_acquire(&file_locked);
	struct file *f = process_get_file(file_description);
	if(!f)
	{
		lock_release(&file_locked);
		return -1;
	}		
	off_t position = file_tell(f);
	
	lock_release(&file_locked);
	return position;
	
}
void close(int file_name)
{
//	struct file *f =  process_get_file(file_description);
	if(file_name == NULL)
	{
		exit(-1);
	}	
	
	lock_acquire(&file_locked);
	process_close_file(file_name);
	lock_release(&file_locked);
}
void get_arg(struct intr_frame *f, int *arg, int n)
{
	int i, *ptr;
	for(i = 0; i < n; i++)
	{
		ptr = (int *) f->esp + i + 1;
		check_address((const void *) ptr);
		arg[i] = *ptr;
	}
}
void check_address(const void *vaddr)
{
	if (vaddr == NULL || vaddr <  ((void *) 0x08048000) || !is_user_vaddr(vaddr))
	{	
		exit(-1);
	}
}
void check_buffer(void* buf, unsigned size)
{
	unsigned i;
	char* local_buffer = (char*) buf;
	for(i=0; i<size; i++)
	{
		check_address((const void*) local_buffer);
		local_buffer++;
	}
}
