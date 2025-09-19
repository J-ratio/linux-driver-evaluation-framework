/*
 * Simple Linux Device Driver Example
 * 
 * This is a basic character device driver that demonstrates
 * fundamental Linux kernel module concepts.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>

#define DEVICE_NAME "simple_driver"
#define CLASS_NAME "simple"
#define BUFFER_SIZE 1024

/* Device variables */
static int major_number;
static struct class* simple_class = NULL;
static struct device* simple_device = NULL;
static char device_buffer[BUFFER_SIZE];
static int buffer_size = 0;

/* Function prototypes */
static int device_open(struct inode *inode, struct file *file);
static int device_release(struct inode *inode, struct file *file);
static ssize_t device_read(struct file *file, char __user *buffer, size_t len, loff_t *offset);
static ssize_t device_write(struct file *file, const char __user *buffer, size_t len, loff_t *offset);

/* File operations structure */
static struct file_operations fops = {
    .open = device_open,
    .read = device_read,
    .write = device_write,
    .release = device_release,
};

/*
 * Module initialization function
 */
static int __init simple_driver_init(void)
{
    printk(KERN_INFO "Simple Driver: Initializing\n");
    
    /* Allocate a major number for the device */
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        printk(KERN_ALERT "Simple Driver: Failed to register major number\n");
        return major_number;
    }
    printk(KERN_INFO "Simple Driver: Registered with major number %d\n", major_number);
    
    /* Register the device class */
    simple_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(simple_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        printk(KERN_ALERT "Simple Driver: Failed to register device class\n");
        return PTR_ERR(simple_class);
    }
    printk(KERN_INFO "Simple Driver: Device class registered\n");
    
    /* Register the device driver */
    simple_device = device_create(simple_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(simple_device)) {
        class_destroy(simple_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        printk(KERN_ALERT "Simple Driver: Failed to create device\n");
        return PTR_ERR(simple_device);
    }
    printk(KERN_INFO "Simple Driver: Device created successfully\n");
    
    return 0;
}

/*
 * Module cleanup function
 */
static void __exit simple_driver_exit(void)
{
    device_destroy(simple_class, MKDEV(major_number, 0));
    class_unregister(simple_class);
    class_destroy(simple_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    printk(KERN_INFO "Simple Driver: Cleanup complete\n");
}

/*
 * Device open function
 */
static int device_open(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "Simple Driver: Device opened\n");
    return 0;
}

/*
 * Device release function
 */
static int device_release(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "Simple Driver: Device closed\n");
    return 0;
}

/*
 * Device read function
 */
static ssize_t device_read(struct file *file, char __user *buffer, size_t len, loff_t *offset)
{
    int bytes_read = 0;
    
    /* Check if we're at the end of the buffer */
    if (*offset >= buffer_size)
        return 0;
    
    /* Don't read past the end of the buffer */
    if (*offset + len > buffer_size)
        len = buffer_size - *offset;
    
    /* Copy data to user space */
    if (copy_to_user(buffer, device_buffer + *offset, len)) {
        return -EFAULT;
    }
    
    *offset += len;
    bytes_read = len;
    
    printk(KERN_INFO "Simple Driver: Read %d bytes\n", bytes_read);
    return bytes_read;
}

/*
 * Device write function
 */
static ssize_t device_write(struct file *file, const char __user *buffer, size_t len, loff_t *offset)
{
    int bytes_written = 0;
    
    /* Don't write past the end of our buffer */
    if (len > BUFFER_SIZE - 1)
        len = BUFFER_SIZE - 1;
    
    /* Copy data from user space */
    if (copy_from_user(device_buffer, buffer, len)) {
        return -EFAULT;
    }
    
    device_buffer[len] = '\0';  /* Null terminate */
    buffer_size = len;
    bytes_written = len;
    
    printk(KERN_INFO "Simple Driver: Wrote %d bytes\n", bytes_written);
    return bytes_written;
}

/* Module macros */
module_init(simple_driver_init);
module_exit(simple_driver_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Driver Evaluation Framework");
MODULE_DESCRIPTION("A simple character device driver for testing");
MODULE_VERSION("1.0");