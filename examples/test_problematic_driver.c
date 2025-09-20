/*
 * Problematic Linux Driver for Testing Compilation and Sparse Analysis
 * 
 * This driver intentionally contains various issues that should be caught
 * by both compilation and sparse analysis tools.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#define DEVICE_NAME "problematic_driver"
#define BUFFER_SIZE 1024

static int major_number;
static struct class* test_class = NULL;
static struct device* test_device = NULL;
static char* device_buffer;
static spinlock_t buffer_lock;

// Function prototypes
static int test_open(struct inode*, struct file*);
static int test_release(struct inode*, struct file*);
static ssize_t test_read(struct file*, char __user*, size_t, loff_t*);
static ssize_t test_write(struct file*, const char __user*, size_t, loff_t*);

static struct file_operations fops = {
    .open = test_open,
    .read = test_read,
    .write = test_write,
    .release = test_release,
};

/**
 * test_init - Initialize the problematic driver
 */
static int __init test_init(void) {
    int unused_variable;  // Warning: unused variable
    
    printk(KERN_INFO "Problematic Driver: Initializing\n");
    
    // Issue 1: Missing null check after allocation
    device_buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL);
    // Should check if device_buffer is NULL here
    
    // Issue 2: Using uninitialized variable
    if (unused_variable > 0) {  // Warning: uninitialized variable
        printk(KERN_INFO "This shouldn't happen\n");
    }
    
    // Register major number
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        printk(KERN_ALERT "Failed to register major number\n");
        kfree(device_buffer);
        return major_number;
    }
    
    // Initialize spinlock
    spin_lock_init(&buffer_lock);
    
    // Create device class
    test_class = class_create(THIS_MODULE, "test");
    if (IS_ERR(test_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        kfree(device_buffer);
        return PTR_ERR(test_class);
    }
    
    // Create device
    test_device = device_create(test_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(test_device)) {
        class_destroy(test_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        kfree(device_buffer);
        return PTR_ERR(test_device);
    }
    
    return 0;
}

/**
 * test_exit - Cleanup the driver
 */
static void __exit test_exit(void) {
    device_destroy(test_class, MKDEV(major_number, 0));
    class_unregister(test_class);
    class_destroy(test_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    kfree(device_buffer);
    printk(KERN_INFO "Problematic Driver: Cleanup complete\n");
}

/**
 * test_open - Handle device open
 */
static int test_open(struct inode *inodep, struct file *filep) {
    printk(KERN_INFO "Problematic Driver: Device opened\n");
    return 0;
}

/**
 * test_release - Handle device close
 */
static int test_release(struct inode *inodep, struct file *filep) {
    printk(KERN_INFO "Problematic Driver: Device closed\n");
    return 0;
}

/**
 * test_read - Handle read operations with address space issues
 */
static ssize_t test_read(struct file *filep, char __user *buffer, size_t len, loff_t *offset) {
    int bytes_to_read;
    char *kernel_buffer;  // Issue: will cause address space problems
    
    // Issue 3: Context imbalance - acquiring lock but not releasing in all paths
    spin_lock(&buffer_lock);
    
    bytes_to_read = min(len, (size_t)(BUFFER_SIZE - *offset));
    
    if (bytes_to_read <= 0) {
        // Issue 4: Missing unlock before return (context imbalance)
        return 0; // Should unlock before returning
    }
    
    // Issue 5: Address space violation - assigning __user pointer to regular pointer
    kernel_buffer = buffer;  // Sparse warning: different address spaces
    
    // Issue 6: Using kernel_buffer instead of proper copy_to_user
    if (copy_to_user(kernel_buffer, device_buffer + *offset, bytes_to_read)) {
        spin_unlock(&buffer_lock);
        return -EFAULT;
    }
    
    *offset += bytes_to_read;
    spin_unlock(&buffer_lock);
    
    return bytes_to_read;
}

/**
 * test_write - Handle write operations with endianness issues
 */
static ssize_t test_write(struct file *filep, const char __user *buffer, size_t len, loff_t *offset) {
    int bytes_to_write;
    __be32 big_endian_value = 0x12345678;  // Big endian value
    u32 host_value;
    
    spin_lock(&buffer_lock);
    
    bytes_to_write = min(len, (size_t)(BUFFER_SIZE - *offset));
    
    if (bytes_to_write <= 0) {
        spin_unlock(&buffer_lock);
        return -ENOSPC;
    }
    
    // Issue 7: Endianness problem - direct assignment without conversion
    host_value = big_endian_value;  // Sparse warning: endianness mismatch
    
    // Issue 8: Bitwise operation on different types
    if (host_value & 0xFF000000) {  // Potential sparse warning
        printk(KERN_INFO "High byte is set\n");
    }
    
    if (copy_from_user(device_buffer + *offset, buffer, bytes_to_write)) {
        spin_unlock(&buffer_lock);
        return -EFAULT;
    }
    
    *offset += bytes_to_write;
    spin_unlock(&buffer_lock);
    
    return bytes_to_write;
}

// Issue 9: Function declared but never defined (will cause linker error)
extern void undefined_function(void);

/**
 * helper_function - Function with cast truncation issues
 */
static void helper_function(void) {
    unsigned long long big_value = 0x123456789ABCDEF0ULL;
    unsigned int small_value;
    
    // Issue 10: Cast truncation - losing significant bits
    small_value = (unsigned int)big_value;  // Sparse warning: cast truncates bits
    
    printk(KERN_INFO "Truncated value: %u\n", small_value);
    
    // Issue 11: Calling undefined function
    // undefined_function();  // Commented out to avoid compilation failure
}

module_init(test_init);
module_exit(test_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Test Framework");
MODULE_DESCRIPTION("A problematic driver for testing analysis tools");
MODULE_VERSION("1.0");