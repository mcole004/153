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

void check_address(const void *vaddr);//checks if pointers are valid
void check_buffer(void* buf, unsigned size); //checks if the buffer is valid
void get_arguments(struct intr_frame *frame, int *argument, int number);  //parses through the argument stack

struct lock file_locked; // dis/enables interrupts
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
	check_address((const void*) f->esp); //check if the frame pointer is valid
	//int esp = user_to_kernel_ptr((const void*) f->esp);
	switch(*(int*)f->esp)//switch(arg[0]) or switch(*(int*)f->esp)
	{
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			get_arguments(f, &arg[0], 1);			
			exit(arg[0]);
			break;
		case SYS_EXEC:
			//arg[1] = user_to_kernel_ptr((const void *) arg[1]);
			//f->eax = exec((char *) arg[1]);
			get_arguments(f, &arg[0], 1);
			f->eax = exec((const char *)arg[0]);
			break;
		case SYS_WAIT:
			get_arguments(f, &arg[0], 1);
			f->eax = wait(arg[0]);
			break;
		case SYS_FILESIZE:
			get_arguments(f, &arg[0], 1);
			f->eax =filesize( arg[0]);
			break;
		case SYS_SEEK:
			get_arguments(f, &arg[0], 2);
			seek(arg[0], (unsigned) arg[1]);
			break;
		case SYS_TELL:
			get_arguments(f, &arg[0], 1);
			f->eax =tell(arg[0]);
			break;
		case SYS_CLOSE:
			get_arguments(f, &arg[0], 1);
			close(arg[0]);
			break;
		case SYS_CREATE:
			get_arguments(f, &arg[0], 2);
			arg[0] = user_to_kernel_ptr((const void *) arg[0]);
			f->eax = create(((const char *)arg[0]), (unsigned) arg[1]);
			break;
		case SYS_REMOVE:
			get_arguments(f, &arg[0], 1);
			arg[0] = user_to_kernel_ptr((const void *)arg[0]);
			f->eax = remove((const char *) arg[0]);
			break;
		case SYS_OPEN:	
			get_arguments(f, &arg[0], 2);
			arg[0] = user_to_kernel_ptr((const void *)arg[0]);
			f->eax =open((char *) arg[0]);
			break;
		case SYS_READ:
			get_arguments(f, &arg[0], 3);
			check_buffer((void *)arg[1], (unsigned) arg[2]);
			arg[1] = user_to_kernel_ptr((const void *)arg[1]);
			f->eax =read(arg[0], (void*)arg[1], (unsigned) arg[2]);
			break;
                case SYS_WRITE:
                        //arg[0] = user_to_kernel_ptr((const void *)arg[0]);
                        get_arguments(f, &arg[0], 3);
			check_buffer((void *)arg[1], (unsigned) arg[2]);
			arg[1] = user_to_kernel_ptr((const void *) arg[1]);
			f->eax = write(arg[0], (const void*)arg[1], (unsigned) arg[2]);	
                        break;
	}
}
/////////////////////////////////////////////HELPER FUNCTIONS
int user_to_kernel_ptr(const void *vaddr)
{
	check_address(vaddr);
	void *pointer = pagedir_get_page(thread_current()->pagedir, vaddr);//located in pagedir.c //returns kernel virtual address that corresponds to the physical address vaddr
	if(!pointer) //if virtual address does not exist, exit
	{
		exit(-1);
	}
	return (int) pointer; //returns virtual address in int form
}
struct file* process_get_file(int file_description) //traverses the list of existing files
{
	struct thread *t = thread_current();
	struct list_elem *e;

	for(e = list_begin(&t->file_list); e != list_end(&t->file_list); e = list_next(e))
	{
		struct process_file *processf = list_entry(e, struct process_file, elem); //list of all processes
		if(file_description == processf->fd) //returns if the process has the same file description. Similar to the thread_check function
		{return processf->file;}
	}
	return NULL;

}
int process_add_file(struct file *f)
 {
  	struct process_file *processfile = malloc(sizeof(struct process_file)); //creates a new array for new files
	 processfile->file = f; //adds the file f into the processfile list
	processfile->fd = thread_current()->fd; //gives the thread's file description to the processfile
	thread_current()->fd++; 
	list_push_back(&thread_current()->file_list, &processfile->elem);
	return processfile->fd;
 }

void process_close_file(int fd)
{
	struct thread *t = thread_current();
	struct list_elem *next, *e = list_begin(&t->file_list);
	while (e != list_end (&t->file_list)) //traverses the list of all files to find the right one to close
	 {
		next = list_next(e);
		struct process_file *pf = list_entry (e, struct process_file, elem);
		if (fd == pf->fd || fd == -1)
		{
			file_close(pf->file); 
			list_remove(&pf->elem); //removes the file from the process list
			free(pf); 
			if (fd != -1)
			{
				return;
			}
		}
		 e = next;
	}
}
void get_arguments(struct intr_frame *frame, int *argument, int number)
{
	int i, *ptr;
	for(i = 0; i < number; i++)
	{
		ptr = (int *) frame->esp + i + 1;
		check_address((const void *) ptr);
		argument[i] = *ptr;
	}
}
void check_address(const void *vaddr)
{
	#define VADDR_CHECK ((void *) 0x08048000)
	if (vaddr <  VADDR_CHECK  || !is_user_vaddr(vaddr))
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
////////////////////////////////////////////////////////////////////SYSCALLS
void halt(void)
{
	shutdown_power_off();
}

int wait (pid_t pid)
{
	return process_wait(pid);
}

void exit (int status)
{
//	struct thread *t = thread_current();    //uncommenting these causes sp-bad-sp & others to fail!
//	t->status = status;
	printf("%s: exit(%d)\n", thread_current()->name, status);
	thread_exit(); 
}
pid_t exec (const char *cmd_line)
{
	check_address(cmd_line);
	pid_t pid = process_execute(cmd_line);
	
	return pid;
}
bool create(const char *file, unsigned initial_size)
{
	lock_acquire(&file_locked);
	bool created = filesys_create(file, initial_size); //located in filesys.c //returns true if created //fails if file already exists
	lock_release(&file_locked);
	return created;
}
bool remove(const char *file)
{
	lock_acquire(&file_locked);
	bool removed = filesys_remove(file); //located in filesys.c //fails if file does not exist
	lock_release(&file_locked);
	return removed;
}
int open(const char *file)
{
	lock_acquire(&file_locked);
	struct file *f = filesys_open(file); //located in src/filesys/filesys.c //opens if the file exists, otherwise returns NULL
	if(!f) //if the file does not open
	{
		lock_release(&file_locked);
		return -1;
	}
	int file_description = process_add_file(f); //adds file to the list of processes
	lock_release(&file_locked);
	return file_description;
}
void close(int file_name)
{
//	struct file *f =  process_get_file(file_description);
	if(file_name == 0)
	{
		exit(-1);
	}	
	
	lock_acquire(&file_locked);
	process_close_file(file_name);
	lock_release(&file_locked);
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


void seek (int file_description, unsigned position)
{	
	lock_acquire(&file_locked);
	struct file *f = process_get_file(file_description);
	if(!f)
	{
		lock_release(&file_locked);
		return ;
	}	
	file_seek(f, position);//located in filesys/file.c //sets the current position in the file to position
	
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
	off_t position = file_tell(f); //returns the current position in the file
	
	lock_release(&file_locked);
	return position;
	
}

int write (int file_description, const void *buffer, unsigned size)
{
	lock_acquire(&file_locked);
	if(file_description == STDOUT_FILENO)
	{
		putbuf(buffer, size);//located in kernel console.c //writes the chacters in *buffer with the number of size into the buffer
		lock_release(&file_locked);
		return size;
	}
	struct file *f = process_get_file(file_description); //finds the file you want to write to
	if(!f) //if the file does not exist, do nothing
	{
		lock_release(&file_locked);
		return -1;
	}
	int written =  file_write(f, buffer, size); //located in src/filesys/file.c //returns number of bytes written to file. This might be smaller than size
	lock_release(&file_locked);
	return written;
}

int read(int fd, void *buffer, unsigned size)
{
	lock_acquire(&file_locked);
	struct file *f = process_get_file(fd);
	if(!f)//if file does not exist
	{
		lock_release(&file_locked);
		return -1;
	}	
	if(fd == STDIN_FILENO)//in stdio.h //stdin_fileno == 0
	{
		unsigned i;
		uint8_t* local_buffer = (uint8_t*)buffer;
		
		for(i = 0; i < size; i++)
		{
			local_buffer[i] = input_getc();
		}
		lock_release(&file_locked);
		return size;	
	}	
	int reading = file_read(f, buffer, size);
	
	lock_release(&file_locked);
	return reading;
}
