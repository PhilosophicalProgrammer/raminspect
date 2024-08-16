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

// We have to declare a module license for this to compile
MODULE_LICENSE("GPL");

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

static int perms_uevent(const struct device *dev, struct kobj_uevent_env *env) {
    add_uevent_var(env, "DEVMODE=%#o", 0600);
    return 0;
}

int raminspect_init(void) {
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
}

module_init(raminspect_init);
module_exit(raminspect_exit);