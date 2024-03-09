// Prelude code needed by all kernel modules
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

// Needing for logging functions
#include <linux/printk.h>

// Needed for manipulating memory regions
#include <linux/mm.h>

// Needed for defining custom device files
#include <linux/device.h>
#include <linux/cdev.h>

// Defines the user-facing interface for interacting with the device file
#include "fops.h"

// We have to put this inside of an ifdef to make VSCode's intellisense stop
// complaining about KBUILD_MODNAME being undefined.

#ifdef KBUILD_MODNAME
    // We have to declare a module license for this to compile
    MODULE_LICENSE("GPL");
#endif

// The major number the kernel chooses to assign when we create our
// temporary device file.
static int major;

// The minor number we assign to the device file
static int minor = 0;

// Linux categorizes device files into different classes to handle them
// better. This virtual device is exclusively used to communicate with
// this particular kernel module so we don't need to use an existing
// class. It requires us to specify a class regardless, however, so
// we specify the name of a new, custom one.

static char* raminspect_classname = "raminspect_backend";
static char* raminspect_devname = "raminspect";
static struct class* raminspect_class;

// Modifies access privileges to the device file to make it readable by
// hijacked user processes not running as root.

static int perms_uevent(const struct device *dev, struct kobj_uevent_env *env) {
    add_uevent_var(env, "DEVMODE=%#o", 0604);
    return 0;
}

int raminspect_init(void) {
    // Initialize the mutexes controlling access to different buffers we use.
    mutex_init(&modified_addr_list_lock);
    mutex_init(&finish_sig_buf_lock);
    mutex_init(&saved_regs_buf_lock);

    // Create a new device file.
    major = register_chrdev(0, raminspect_devname, &raminspect_fops);

    // Handle errors.
    if(major < 0) pr_alert("Registering device file failed with code: %d", major);

    raminspect_class = class_create(raminspect_classname);
    raminspect_class -> dev_uevent = perms_uevent;

    device_create(raminspect_class, NULL, MKDEV(major, minor), NULL, raminspect_devname);
    return 0;
}

void raminspect_exit(void) {
    // Destroy the device file and class.
    device_destroy(raminspect_class, MKDEV(major, minor));
    class_destroy(raminspect_class);

    // Unregister the device.
    unregister_chrdev(major, raminspect_devname);

    // Free allocated resources.
    mutex_destroy(&finish_sig_buf_lock);
    mutex_destroy(&saved_regs_buf_lock);
    mutex_destroy(&modified_addr_list_lock);

    if(finish_sig_buf.buffer != NULL) {
        kfree(finish_sig_buf.buffer);
    }

    if(modified_addr_list.buffer != NULL) {
        kfree(modified_addr_list.buffer);
    }

    if(saved_regs_buf.buffer != NULL) {
        uintptr_t i;
        for(i = 0; i < saved_regs_buf.length; i++) {
            kfree((void*)(saved_regs_buf.buffer[i]));
        }

        kfree(saved_regs_buf.buffer);
    }
}

module_init(raminspect_init);
module_exit(raminspect_exit);