// Needed for the ioctl-based interface
#include <linux/ioctl.h>
#include <asm/ioctl.h>

// Needed for sleeping
#include <asm/delay.h>

// Needed to access process registers
#include <linux/sched/task_stack.h>

// Saved process state for later restoration
typedef struct {
    int pid;
    struct pt_regs regs;
} SavedRegisters;

// A growable buffer of pointer-sized integers, similar in behavior to 
// a Rust or C++ vector.

typedef struct {
    uintptr_t* buffer;
    uintptr_t length;
    uintptr_t capacity;
} NumberBuffer;

static void push_to_buffer(NumberBuffer* buffer, uintptr_t address) {
    if(buffer -> buffer == NULL) {
        buffer -> capacity = 100;
        buffer -> buffer = kmalloc(buffer -> capacity * sizeof(uintptr_t), GFP_KERNEL);
    }

    if(buffer -> length == buffer -> capacity) {
        buffer -> capacity *= 2;
        uintptr_t new_buf_size = buffer -> capacity * sizeof(uintptr_t);
        uintptr_t* old_buffer = buffer -> buffer;

        uintptr_t* new_buffer = kmalloc(new_buf_size, GFP_KERNEL);
        memcpy(new_buffer, old_buffer, (buffer -> length) * sizeof(uintptr_t));
        buffer -> buffer = new_buffer;
        kfree(old_buffer);
    }

    (buffer -> length)++;
    (buffer -> buffer)[buffer -> length - 1] = address;
}

static void swap_remove_index(NumberBuffer* buffer, uintptr_t index) {
    if(buffer -> length > 1) {
        (buffer -> buffer)[index] = (buffer -> buffer)[buffer -> length - 1];
    }

    (buffer -> length)--;
}

// A list of modified VMAs represented by their unique starting address in their
// process.

static NumberBuffer modified_addr_list;
DEFINE_MUTEX(modified_addr_list_lock);

// A list of hijacked process IDs which have sent an unacknowledged finishing signal to 
// the kernel module. Used in the WAIT_FOR_FINISH command.
static NumberBuffer finish_sig_buf;
DEFINE_MUTEX(finish_sig_buf_lock);

// A list of pointers to saved process register states for later restoration by the hijacker
// so that program execution can continue as if nothing happened after their shellcode
// finishes executing.

static NumberBuffer saved_regs_buf;
DEFINE_MUTEX(saved_regs_buf_lock);

typedef struct {
    int pid;
    uint64_t instruction_pointer;
} InstructionPointerRequest;

#define RS_MAGIC 123
#define WAIT_FOR_FINISH _IOW(RS_MAGIC, 0, int)
#define TOGGLE_EXEC_WRITE _IOW(RS_MAGIC, 1, int)
#define GET_INST_PTR _IOWR(RS_MAGIC, 2, InstructionPointerRequest)
#define RESTORE_REGS _IOW(RS_MAGIC, 3, int)

static long raminspect_ioctl(struct file *fptr, unsigned int cmd, unsigned long arg) {
    switch(cmd) {
        case TOGGLE_EXEC_WRITE: {
            int pid = (int)arg;
            struct task_struct* task = pid_task(find_vpid(pid), PIDTYPE_PID);

            if(task == NULL) {
                pr_alert("Error: The target process was not running!\n");
                return -EINVAL;
            }

            struct vm_area_struct* current_vma;
            struct mm_struct* mm = task -> mm;

            VMA_ITERATOR(vmi, mm, 0);
            for_each_vma(vmi, current_vma) {
                unsigned long vma_start = current_vma->vm_start;
                vm_flags_t flags = current_vma -> vm_flags;

                if((flags & VM_EXEC) != 0) {
                    mutex_lock(&modified_addr_list_lock);

                    unsigned long i;
                    unsigned long addr_index;
                    
                    bool found_addr = false;
                    for(i = 0; i < modified_addr_list.length; i++) {
                        if(modified_addr_list.buffer[i] == vma_start) {
                            addr_index = i;
                            break;
                        }
                    }
                    
                    if(found_addr) {
                        swap_remove_index(&modified_addr_list, addr_index);
                        vm_flags_set(current_vma, (current_vma -> vm_flags) & ~VM_WRITE);
                    } else if((flags & VM_WRITE) == 0) {
                        push_to_buffer(&modified_addr_list, vma_start);
                        vm_flags_set(current_vma, (current_vma -> vm_flags) | VM_WRITE);
                    }

                    mutex_unlock(&modified_addr_list_lock);
                }
            }

            break;
        }

        case WAIT_FOR_FINISH: {
            int pid = (int)arg;
            uintptr_t index = 0;
            bool found_index = false;

            while(!found_index) {
                if(pid_task(find_vpid(pid), PIDTYPE_PID) == NULL) {
                    pr_alert("Error: The hijacked process unexpectedly terminated.\n");
                    return -ECANCELED;
                }

                uintptr_t i;
                mutex_lock(&finish_sig_buf_lock);
                for(i = 0; i < finish_sig_buf.length; i++) {
                    if(finish_sig_buf.buffer[i] == pid) {
                        found_index = true;
                        index = i;
                        break;
                    }
                }

                if(found_index) {
                    swap_remove_index(&finish_sig_buf, index);
                }

                mutex_unlock(&finish_sig_buf_lock);
                udelay(1);
            }
            
            break;
        }

        case GET_INST_PTR: {
            void* data_ptr = (void*)arg;
            InstructionPointerRequest request;
            if(copy_from_user(&request, data_ptr, sizeof(InstructionPointerRequest)) != 0) {
                pr_alert("Error: Failed to copy instruction pointer request data from user\n");
                return -EINVAL;
            }

            struct task_struct* task = pid_task(find_vpid(request.pid), PIDTYPE_PID);

            if(task == NULL) {
                pr_alert("Error: The target process was not running!\n");
                return -EINVAL;
            }

            struct pt_regs* regs = task_pt_regs(task);
            SavedRegisters* allocated_regs = kmalloc(sizeof(SavedRegisters), GFP_KERNEL);

            allocated_regs -> regs = *regs;
            allocated_regs -> pid = request.pid;

            mutex_lock(&saved_regs_buf_lock);
            push_to_buffer(&saved_regs_buf, (uintptr_t)(allocated_regs));
            mutex_unlock(&saved_regs_buf_lock);

            request.instruction_pointer = instruction_pointer(regs);
            if(copy_to_user(data_ptr, &request, sizeof(InstructionPointerRequest)) != 0) {
                pr_alert("Error: Failed to copy instruction pointer request data to user\n");
                return -EINVAL;
            }

            break;
        }

        case RESTORE_REGS: {
            uintptr_t i;
            int pid = (int)arg;
            struct task_struct* task = pid_task(find_vpid(pid), PIDTYPE_PID);

            if(task == NULL) {
                pr_alert("Error: The target process is not currently running!\n");
                return -EINVAL;
            }

            bool found_pid = false;
            uintptr_t pid_index = 0;
            mutex_lock(&saved_regs_buf_lock);
            for(i = 0; i < saved_regs_buf.length; i++) {
                if(((SavedRegisters*)(saved_regs_buf.buffer[i])) -> pid == pid) {
                    found_pid = true;
                    pid_index = i;
                    break;
                }
            }

            if(!found_pid) {
                pr_alert("Error: No such process has had its registers saved!\n");
                mutex_unlock(&saved_regs_buf_lock);
                return -EINVAL;
            }

            *task_pt_regs(task) = ((SavedRegisters*)(saved_regs_buf.buffer[pid_index])) -> regs;
            kfree((void*)(saved_regs_buf.buffer[pid_index]));
            swap_remove_index(&saved_regs_buf, pid_index);
            mutex_unlock(&saved_regs_buf_lock);
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

int no_op_open(struct inode* _file_info, struct file* _file) {
    return 0;
}

int no_op_close(struct inode* _file_info, struct file* _file) {
    return 0;
}

// A read of exactly one byte acts as a finishing signal given by a hijacked process.
// All other reads are no-ops.

ssize_t maybe_finish_signal(struct file *fptr, char __user *buffer, size_t blen, loff_t *offs) {
    if(blen == 1) {
        mutex_lock(&finish_sig_buf_lock);
        
        uintptr_t i;
        int pid_num = current -> pid;
        pr_info("Notice: Got finishing signal from process with PID %d\n", pid_num);
        
        // If we already received an unacknowledged finishing signal from this process
        // we won't waste extra memory in the buffer.

        for(i = 0; i < finish_sig_buf.length; i++) {
            if(finish_sig_buf.buffer[i] == pid_num) {
                pr_alert("Error: Got duplicate finishing signal from process with PID %d\n", pid_num);
                mutex_unlock(&finish_sig_buf_lock);
                return -EINVAL;
            }
        }

        push_to_buffer(&finish_sig_buf, pid_num);
        mutex_unlock(&finish_sig_buf_lock);
        return 0;
    }

    pr_alert("Error: Got invalid read with buffer length of %ld\n", blen);
    return -EINVAL;
}

ssize_t no_op_write(struct file *fptr, const char __user *buffer, size_t buf_len, loff_t *offs) {
    return 0;
}

static struct file_operations raminspect_fops = {
    .open = no_op_open,
    .write = no_op_write,
    .release = no_op_close,
    .read = maybe_finish_signal,
    .unlocked_ioctl = raminspect_ioctl,
};