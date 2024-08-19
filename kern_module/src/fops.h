// Needed for the ioctl-based interface
#include <linux/ioctl.h>
#include <asm/ioctl.h>

// Needed to access process registers
#include <linux/sched/task_stack.h>

// The magic number for our `ioctl` definitions. 'r' stands for raminspect. Note: Any changes made to the `ioctl`
// interface in this file must also be made in the Rust bindings to it to maintain compatibility.
#define RAMINSPECT_MAGIC 'r'

// These commands allow a privileged user process to read and write the registers and signal masks
// of the threads of an arbitrary process. This forms the core basis of the functionality of our
// framework, and allows for precise control over the state of a process and its execution.

#define GET_THREADS _IOWR(RAMINSPECT_MAGIC, 0, struct thread_request)
#define SET_THREADS _IOWR(RAMINSPECT_MAGIC, 1, struct thread_request)

// These commands allow a privileged user process to arbitrarily control the access privileges (readability,
// writability, and executability) of another process. This is important for shellcode execution, since it
// is desirable in that situation to want to overwrite not-usually-writable data at the address of the
// instruction pointer of the target process.

#define GET_VMA_FLAGS _IOWR(RAMINSPECT_MAGIC, 2, struct vma_flags_request)
#define SET_VMA_FLAGS _IOWR(RAMINSPECT_MAGIC, 3, struct vma_flags_request)

// This is sent to and received back from a process using the `*_THREADS` ioctls. It contains
// the thread ID that the data belongs to in the case of `GET_THREADS`, or the thread ID of
// the thread to write this data to in the case of `SET_THREADS`. It contains information
// about the signal mask and registers of the target thread.

struct thread_data {
    struct pt_regs registers;
    sigset_t sigmask;
    pid_t thread_id;
};

// This is used in the `*_THREADS` ioctls. It contains a buffer of `thread_data` structures, the
// process ID that they all belong to, and the length of the buffer.
//
// In the case of `GET_THREADS`, the buffer is uninitialized and can hold a maximum of `buf_len` elements,
// and the thread data retrieved by this module from the process will be written into it, updating the
// buffer length to represent the amount of threads retrieved. If the given buffer length is too small
// to hold all of the threads, an `ERANGE` error code will be given to the user and they'll have to
// retry with a larger buffer.
//
// In the case of `SET_THREADS`, the buffer is not uninitialized, and the buffer length represents the
// amount of thread data that was given by the user. Invalid thread IDs will be ignored, and valid
// thread IDs will have their signal masks and registers updated to match their provided data.

struct thread_request {
    struct thread_data* threadbuf;
    size_t buf_len;
    pid_t pid;
};

// This is used in the `*_VMA_FLAGS` ioctls. It contains a process ID, the start and end address of
// a memory region within this process, and a set of flags to either get or set, depending on
// whether or not it's a `GET_VMA_FLAGS` or `SET_VMA_FLAGS` call.

struct vma_flags_request {
    uintptr_t vma_start;
    uintptr_t vma_end;
    vm_flags_t flags;
    pid_t pid;
};

// This eliminates code duplication across the different `ioctl` commands. It copies a request structure of
// the specified type from the user, and then uses the provided `pid` field to fetch the `task_struct` to
// modify. This can't be a function since it has to be able to terminate the caller on error.

#define setup_ioctl(reqty) \
    struct reqty request; \
    void* data_ptr = (void*)arg; \
    if(copy_from_user(&request, data_ptr, sizeof(struct reqty)) != 0) { \
        pr_alert("Error: Failed to copy request data from user\n"); \
        return -EFAULT; \
    } \
    \
    struct task_struct* task = pid_task(find_vpid(request.pid), PIDTYPE_PID); \
    \
    if(task == NULL) { \
        pr_alert("Error: The target process was not running\n"); \
        return -ESRCH; \
    }

static long raminspect_ioctl(struct file *fptr, unsigned int cmd, unsigned long arg) {
    switch(cmd) {
        case GET_THREADS:
        case SET_THREADS:
        
        {
            setup_ioctl(thread_request);
            size_t buf_size = request.buf_len * sizeof(struct thread_data);
            struct thread_data* buffer = kmalloc(buf_size, GFP_KERNEL);

            if(buffer == NULL) {
                pr_alert("Error: Failed to allocate thread data buffer\n");
                return -ENOMEM;
            }

            struct task_struct* thread;

            if(cmd == GET_THREADS) {
                // The amount of threads copied so far.
                size_t copy_count = 0;

                rcu_read_lock();
                for_each_thread(task, thread) {
                    if(copy_count >= request.buf_len) {
                        // If the buffer is too small, we return -ERANGE to tell the user to retry with a larger buffer.
                        rcu_read_unlock();
                        kfree(buffer);
                        return -ERANGE;
                    }

                    task_lock(thread);
                    buffer[copy_count++] = (struct thread_data){
                        .registers = *task_pt_regs(thread),
                        .sigmask = thread->blocked,
                        .thread_id = thread->pid
                    };

                    task_unlock(thread);
                }

                rcu_read_unlock();
                if(copy_to_user((void*)request.threadbuf, (void*)buffer, copy_count * sizeof(struct thread_data)) != 0) {
                    pr_alert("Error: Failed to copy thread buffer to user\n");
                    kfree(buffer);
                    return -EFAULT;
                }

                kfree(buffer);
                request.buf_len = copy_count;
                if(copy_to_user(data_ptr, (void*)&request, sizeof(struct thread_request)) != 0) {
                    pr_alert("Error: Failed to copy thread request to user\n");
                    return -EFAULT;
                }
            } else {
                // Get thread data from the user.
                if(copy_from_user(buffer, request.threadbuf, buf_size) != 0) {
                    pr_alert("Error: Failed to copy thread buffer from user\n");
                    kfree(buffer);
                    return -EFAULT;
                }

                // Update the threads that match the given thread IDs.

                rcu_read_lock();
                for_each_thread(task, thread) {
                    for(int i = 0; i < request.buf_len; i++) {
                        struct thread_data curr_thread = buffer[i];

                        if(thread->pid == curr_thread.thread_id) {
                            task_lock(thread);
                            thread->blocked = curr_thread.sigmask;
                            *task_pt_regs(thread) = curr_thread.registers;
                            task_unlock(thread);
                            break;
                        }
                    }
                }

                rcu_read_unlock();
                kfree(buffer);
            }

            break;
        }

        case GET_VMA_FLAGS:
        case SET_VMA_FLAGS:
        
        {
            setup_ioctl(vma_flags_request);
            struct vm_area_struct* vma = find_exact_vma(task->mm, request.vma_start, request.vma_end);

            if(vma == NULL) {
                pr_alert("Error: Failed to find VMA with specified range\n");
                return -ENODATA;
            }

            if(cmd == SET_VMA_FLAGS) {
                vm_flags_set(vma, request.flags);
            } else {
                request.flags = vma->vm_flags;
                if(copy_to_user(data_ptr, &request, sizeof(struct vma_flags_request)) != 0) {
                    pr_alert("Error: Failed to copy VMA flags to user\n");
                    return -EFAULT;
                }
            }

            break;
        }

        default:

        {
            pr_alert("Invalid ioctl command\n");
            return -ENOTTY;
        }
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