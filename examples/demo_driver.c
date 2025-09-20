/*
 * Simple Linux Character Device Driver Demo
 * 
 * This is a basic character device driver that demonstrates
 * fundamental Linux kernel module concepts.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define DEVICE_NAME "demo_driver"
#define CLASS_NAME "demo"
#define BUFFER_SIZE 1024

static int major_number;
static struct class* demo_class = NULL;
static struct device* demo_device = NULL;
static char* device_buffer;
static int buffer_size = 0;

// Function prototypes
static int demo_open(struct inode*, struct file*);
static int demo_release(struct inode*, struct file*);
static ssize_t demo_read(struct file*, char*, size_t, loff_t*);
static ssize_t demo_write(struct file*, const char*, size_t, loff_t*);

// File operations structure
static struct file_operations fops = {
    .open = demo_open,
    .read = demo_read,
    .write = demo_write,
    .release = demo_release,
};

/**
 * demo_init - Initialize the driver
 */
static int __init demo_init(void) {
    printk(KERN_INFO "Demo Driver: Initializing\n");
    
    // Allocate device buffer
    device_buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL);
    if (!device_buffer) {
        printk(KERN_ALERT "Demo Driver: Failed to allocate buffer\n");
        return -ENOMEM;
    }
    
    // Register major number
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        printk(KERN_ALERT "Demo Driver: Failed to register major number\n");
        kfree(device_buffer);
        return major_number;
    }
    
    // Create device class
    demo_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(demo_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        kfree(device_buffer);
        printk(KERN_ALERT "Demo Driver: Failed to create class\n");
        return PTR_ERR(demo_class);
    }
    
    // Create device
    demo_device = device_create(demo_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(demo_device)) {
        class_destroy(demo_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        kfree(device_buffer);
        printk(KERN_ALERT "Demo Driver: Failed to create device\n");
        return PTR_ERR(demo_device);
    }
    
    printk(KERN_INFO "Demo Driver: Successfully initialized with major number %d\n", major_number);
    return 0;
}

/**
 * demo_exit - Cleanup the driver
 */
static void __exit demo_exit(void) {
    device_destroy(demo_class, MKDEV(major_number, 0));
    class_unregister(demo_class);
    class_destroy(demo_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    kfree(device_buffer);
    printk(KERN_INFO "Demo Driver: Cleanup complete\n");
}

/**
 * demo_open - Handle device open
 */
static int demo_open(struct inode *inodep, struct file *filep) {
    printk(KERN_INFO "Demo Driver: Device opened\n");
    return 0;
}

/**
 * demo_release - Handle device close
 */
static int demo_release(struct inode *inodep, struct file *filep) {
    printk(KERN_INFO "Demo Driver: Device closed\n");
    return 0;
}

/**
 * demo_read - Handle read operations
 */
static ssize_t demo_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {
    int bytes_to_read = min(len, (size_t)(buffer_size - *offset));
    
    if (bytes_to_read <= 0) {
        return 0; // EOF
    }
    
    if (copy_to_user(buffer, device_buffer + *offset, bytes_to_read)) {
        return -EFAULT;
    }
    
    *offset += bytes_to_read;
    printk(KERN_INFO "Demo Driver: Read %d bytes\n", bytes_to_read);
    return bytes_to_read;
}

/**
 * demo_write - Handle write operations
 */
static ssize_t demo_write(struct file *filep, const char *buffer, size_t len, loff_t *offset) {
    int bytes_to_write = min(len, (size_t)(BUFFER_SIZE - *offset));
    
    if (bytes_to_write <= 0) {
        return -ENOSPC; // No space left
    }
    
    if (copy_from_user(device_buffer + *offset, buffer, bytes_to_write)) {
        return -EFAULT;
    }
    
    *offset += bytes_to_write;
    buffer_size = max(buffer_size, (int)*offset);
    
    printk(KERN_INFO "Demo Driver: Wrote %d bytes\n", bytes_to_write);
    return bytes_to_write;
}

module_init(demo_init);
module_exit(demo_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Driver Evaluation Framework");
MODULE_DESCRIPTION("A simple character device driver for demonstration");
MODULE_VERSION("1.0");