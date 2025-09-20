/*
 * Problematic Driver Example
 * 
 * This driver intentionally contains various issues that the evaluation
 * framework should detect, including security vulnerabilities, poor coding
 * practices, and potential bugs.
 * 
 * WARNING: This code is for demonstration purposes only and contains
 * intentional security vulnerabilities. Do not use in production!
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>

#define DEVICE_NAME "problematic_dev"
#define BUFFER_SIZE 256

static int major_number;
static struct class* prob_class = NULL;
static struct device* prob_device = NULL;
static char device_buffer[BUFFER_SIZE];
static char user_data[100];  // Fixed size buffer - potential overflow

// Function prototypes
static int prob_open(struct inode*, struct file*);
static int prob_release(struct inode*, struct file*);
static ssize_t prob_read(struct file*, char*, size_t, loff_t*);
static ssize_t prob_write(struct file*, const char*, size_t, loff_t*);

static struct file_operations fops = {
    .open = prob_open,
    .read = prob_read,
    .write = prob_write,
    .release = prob_release,
};

/**
 * prob_init - Initialize the problematic driver
 */
static int __init prob_init(void) {
    int result;
    
    printk("Problematic Driver: Starting initialization\n");  // Missing KERN_* level
    
    // Register character device - no error checking
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    
    // Create class - minimal error handling
    prob_class = class_create(THIS_MODULE, "prob");
    if(prob_class == NULL) {
        unregister_chrdev(major_number, DEVICE_NAME);
        return -1;  // Should use proper error codes
    }

    // Create device
    prob_device = device_create(prob_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if(prob_device == NULL) {
        class_destroy(prob_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        return -1;
    }

    // Initialize buffer with potentially unsafe operation
    strcpy(device_buffer, "Default data");  // Should use strncpy
    
    printk("Problematic Driver: Initialized with major number %d\n", major_number);
    return 0;
}

/**
 * prob_exit - Cleanup (incomplete cleanup)
 */
static void __exit prob_exit(void) {
    device_destroy(prob_class, MKDEV(major_number, 0));
    class_destroy(prob_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    // Missing: should zero out sensitive data in buffers
    printk("Problematic Driver: Exiting\n");
}

/**
 * prob_open - Open device (no access control)
 */
static int prob_open(struct inode *inodep, struct file *filep) {
    // No access control or resource management
    printk("Problematic Driver: Device opened\n");
    return 0;
}

/**
 * prob_release - Release device
 */
static int prob_release(struct inode *inodep, struct file *filep) {
    printk("Problematic Driver: Device closed\n");
    return 0;
}

/**
 * prob_read - Read from device (buffer overflow potential)
 */
static ssize_t prob_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {
    int bytes_read = 0;
    
    // Dangerous: no bounds checking
    if(*offset >= BUFFER_SIZE) return 0;
    
    // Potential buffer overflow
    if(len > BUFFER_SIZE) len = BUFFER_SIZE;
    
    // Copy without proper error checking
    if(copy_to_user(buffer, device_buffer + *offset, len)) {
        return -EFAULT;
    }
    
    *offset += len;
    bytes_read = len;
    
    printk("Problematic Driver: Read %d bytes\n", bytes_read);
    return bytes_read;
}

/**
 * prob_write - Write to device (multiple vulnerabilities)
 */
static ssize_t prob_write(struct file *filep, const char *buffer, size_t len, loff_t *offset) {
    char temp_buffer[50];  // Small buffer
    
    printk("Problematic Driver: Writing %zu bytes\n", len);
    
    // Vulnerability 1: Buffer overflow - copying user data without size check
    if(copy_from_user(user_data, buffer, len)) {  // Should check len against sizeof(user_data)
        return -EFAULT;
    }
    
    // Vulnerability 2: Using dangerous string functions
    strcpy(temp_buffer, user_data);  // Potential overflow
    strcat(device_buffer, temp_buffer);  // Another potential overflow
    
    // Vulnerability 3: No null termination guarantee
    // user_data might not be null-terminated
    
    // Race condition: no locking mechanism
    // Multiple processes could write simultaneously
    
    // Information leak: not clearing sensitive data
    // temp_buffer contents remain in stack
    
    return len;  // Always return success, even on partial writes
}

// Missing proper error handling throughout
// No input validation
// No resource cleanup on errors
// Unsafe string operations
// No access control
// Race conditions possible
// Information disclosure risks

module_init(prob_init);
module_exit(prob_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Evaluation Framework Demo");
MODULE_DESCRIPTION("Intentionally problematic driver for testing evaluation framework");
MODULE_VERSION("1.0");