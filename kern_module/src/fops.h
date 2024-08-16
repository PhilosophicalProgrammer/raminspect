// Needed for the ioctl-based interface
#include <linux/ioctl.h>
#include <asm/ioctl.h>

// Needed to access process registers
#include <linux/sched/task_stack.h>
#include "plist.h"

struct thread_data {
    struct pt_regs registers;
    sigset_t sigmask;
    pid_t thread_id;
};

struct thread_request {
    pid_t pid;
    size_t buf_len;
    struct thread_data* threadbuf;
};

struct task_list {
    pid_t pid;
    struct pointer_list tasks;
    unsigned long descheduled_at;
};

// List of pointers to task lists. See above.
static struct pointer_list task_lists;
DEFINE_MUTEX(task_lists_mutex);

#define RS_MAGIC 123
#define GET_THREADS _IOWR(RS_MAGIC, 0, struct thread_request*)
#define SET_THREADS _IOWR(RS_MAGIC, 1, struct thread_request*)
#define DESCHED_THREADS _IOW(RS_MAGIC, 2, unsigned long)
#define RESCHED_THREADS _IOW(RS_MAGIC, 3, unsigned long)
#define REMOTE_MPROTECT _IOW(RS_MAGIC, 4, uintptr_t) 

static long raminspect_ioctl(struct file *fptr, unsigned int cmd, unsigned long arg) {
    switch(cmd) {
        case GET_THREADS:
        case SET_THREADS:
        
        {
            void* data_ptr = (void*)arg;
            struct thread_request request;
            if(copy_from_user(&request, data_ptr, sizeof(struct thread_request)) != 0) {
                pr_alert("Error: Failed to copy thread request data from user\n");
                return -EINVAL;
            }

            struct task_struct* thread;
            struct task_struct* task = pid_task(find_vpid(request.pid), PIDTYPE_PID);

            if(task == NULL) {
                pr_alert("Error: The target process was not running\n");
                return -EINVAL;
            }

            size_t buf_size = request.buf_len * sizeof(struct thread_data);
            struct thread_data* buffer = kmalloc(buf_size, GFP_KERNEL);

            if(cmd == GET_THREADS) {
                size_t copy_count = 0;

                rcu_read_lock();
                for_each_thread(task, thread) {
                    if(copy_count >= request.buf_len) {
                        rcu_read_unlock();
                        kfree(buffer);
                        return -ERANGE;
                    }

                    buffer[copy_count++] = (struct thread_data){
                        .registers = *task_pt_regs(thread),
                        .sigmask = thread->blocked,
                        .thread_id = thread->pid
                    };
                }

                rcu_read_unlock();
                if(copy_to_user((void*)request.threadbuf, (void*)buffer, copy_count * sizeof(struct thread_data)) != 0) {
                    pr_alert("Error: Failed to copy thread buffer to user\n");
                    kfree(buffer);
                    return -EINVAL;
                }

                kfree(buffer);
                request.buf_len = copy_count;
                if(copy_to_user(data_ptr, (void*)&request, sizeof(struct thread_request)) != 0) {
                    pr_alert("Error: Failed to copy thread request to user\n");
                    return -EINVAL;
                }
            } else {

                if(copy_from_user(buffer, request.threadbuf, buf_size) != 0) {
                    pr_alert("Error: Failed to copy thread buffer from user\n");
                    kfree(buffer);
                    return -EINVAL;
                }

                rcu_read_lock();
                for_each_thread(task, thread) {
                    for(int i = 0; i < request.buf_len; i++) {
                        struct thread_data curr_thread = buffer[i];

                        if(thread->pid == curr_thread.thread_id) {
                            thread->blocked = curr_thread.sigmask;
                            *task_pt_regs(thread) = curr_thread.registers;
                            break;
                        }
                    }
                }

                rcu_read_unlock();
                kfree(buffer);
            }

            break;
        }

        case DESCHED_THREADS:
        
        {
            // The process ID is provided directly as an argument to the `ioctl` call.
            struct task_struct* task = pid_task(find_vpid(arg), PIDTYPE_PID);

            if(task == NULL) {
                pr_alert("Error: The target process was not running\n");
                return -EINVAL;
            }

            // We don't modify the task list while iterating over it in order to avoid undefined behavior.
            // Instead, we allocate a growable list of task pointers, store all threads of the provided
            // PID in that, and then iterate over that once we're done collecting it.
            struct pointer_list* task_list = kzalloc(sizeof(struct pointer_list), GFP_KERNEL);

            rcu_read_lock();
            struct task_struct* thread;
            for_each_thread(task, thread) {
                push_pointer(task_list, (uintptr_t)thread);
            }

            rcu_read_unlock();
            // Now we can adjust the task list accordingly and remove the tasks from it.

            write_lock(&tasklist_lock);
            for(int i = 0; i < task_list->length; i++) {
                struct task_struct* task = (struct task_struct*)task_list->data[i];
                list_del_rcu(&task->tasks);
            }

            write_unlock(&tasklist_lock);
            // Since the user will probably reschedule these tasks later, we should store the list for retrieval.

            mutex_lock(&task_lists_mutex);
            push_pointer(&task_lists, (uintptr_t)task_list);
            mutex_unlock(&task_lists_mutex);
            break;
        }

        case RESCHED_THREADS:

        {
            reschedule_threads(arg);
            break;
        }

        case REMOTE_MPROTECT:
        
        {
            break;
        }

        default:
            pr_alert("Invalid ioctl command\n");
            return -EINVAL;
    }

    return 0;
}

// There are no restrictions on multiple programs or threads doing multiple 
// operations at once, so we don't need to lock / release anything in the 
// open and close handlers.

static int no_op_open(struct inode* _file_info, struct file* _file) {
    return 0;
}

static int no_op_close(struct inode* _file_info, struct file* _file) {
    return 0;
}

// Reads and writes should also do nothing.
static ssize_t no_op_read(struct file *fptr, char __user *buffer, size_t buf_len, loff_t *offs) {
    return 0;
}

static ssize_t no_op_write(struct file *fptr, const char __user *buffer, size_t buf_len, loff_t *offs) {
    return 0;
}

static struct file_operations raminspect_fops = {
    .open = no_op_open,
    .read = no_op_read,
    .write = no_op_write,
    .release = no_op_close,
    .unlocked_ioctl = raminspect_ioctl,
};