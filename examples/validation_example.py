#!/usr/bin/env python3
"""
Example script demonstrating the input validation and preprocessing functionality.
"""

import sys
import os

# Add the src directory to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from models.evaluation import SourceFile
from services.validation import InputValidator


def main():
    """Demonstrate validation functionality with example driver code."""
    
    # Example 1: Valid character device driver
    char_driver_code = """
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>

#define DEVICE_NAME "mychardev"
#define CLASS_NAME "mychar"

static int major_number;
static struct class* char_class = NULL;
static struct device* char_device = NULL;

static int device_open(struct inode *inodep, struct file *filep) {
    printk(KERN_INFO "MyCharDev: Device opened\\n");
    return 0;
}

static int device_release(struct inode *inodep, struct file *filep) {
    printk(KERN_INFO "MyCharDev: Device closed\\n");
    return 0;
}

static ssize_t device_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {
    // Implementation here
    return 0;
}

static ssize_t device_write(struct file *filep, const char *buffer, size_t len, loff_t *offset) {
    // Implementation here
    return len;
}

static struct file_operations fops = {
    .open = device_open,
    .read = device_read,
    .write = device_write,
    .release = device_release,
};

static int __init char_driver_init(void) {
    printk(KERN_INFO "MyCharDev: Initializing\\n");
    
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        printk(KERN_ALERT "MyCharDev: Failed to register major number\\n");
        return major_number;
    }
    
    char_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(char_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        printk(KERN_ALERT "MyCharDev: Failed to register device class\\n");
        return PTR_ERR(char_class);
    }
    
    char_device = device_create(char_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(char_device)) {
        class_destroy(char_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        printk(KERN_ALERT "MyCharDev: Failed to create device\\n");
        return PTR_ERR(char_device);
    }
    
    printk(KERN_INFO "MyCharDev: Device registered with major number %d\\n", major_number);
    return 0;
}

static void __exit char_driver_exit(void) {
    device_destroy(char_class, MKDEV(major_number, 0));
    class_unregister(char_class);
    class_destroy(char_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    printk(KERN_INFO "MyCharDev: Device unregistered\\n");
}

module_init(char_driver_init);
module_exit(char_driver_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Example Author");
MODULE_DESCRIPTION("A simple character device driver");
MODULE_VERSION("1.0");
"""

    # Example 2: Code with syntax errors
    bad_code = """
#include <linux/module.h>

static int __init bad_init(void) {
    printk("Missing closing brace");
    return 0;
// Missing }

MODULE_LICENSE("GPL");
"""

    # Example 3: Non-driver code
    regular_c_code = """
#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    strcpy(buffer, "dangerous");  // This should trigger a warning
    printf("Hello, World!\\n");
    return 0;
}
"""

    # Create source file objects
    examples = [
        ("Character Device Driver", SourceFile("char_driver.c", char_driver_code, len(char_driver_code))),
        ("Code with Syntax Errors", SourceFile("bad_code.c", bad_code, len(bad_code))),
        ("Regular C Code", SourceFile("regular.c", regular_c_code, len(regular_c_code)))
    ]
    
    # Initialize validator
    validator = InputValidator()
    
    print("Linux Driver Evaluation Framework - Validation Examples")
    print("=" * 60)
    
    for name, source_file in examples:
        print(f"\\n{name}:")
        print("-" * len(name))
        
        # Validate the source file
        result = validator.validate_source_file(source_file)
        
        print(f"Valid: {result.is_valid}")
        print(f"Driver Type: {result.driver_type.value}")
        print(f"Complexity Score: {result.complexity_score}")
        
        if result.detected_features:
            print(f"Detected Features: {', '.join(result.detected_features)}")
        
        if result.errors:
            print("Errors:")
            for error in result.errors:
                print(f"  - {error}")
        
        if result.warnings:
            print("Warnings:")
            for warning in result.warnings:
                print(f"  - {warning}")
    
    # Demonstrate preprocessing multiple files
    print("\\n\\nMultiple Files Preprocessing:")
    print("-" * 30)
    
    valid_files = [ex[1] for ex in examples if validator.validate_source_file(ex[1]).is_valid]
    preprocessing_result = validator.preprocess_for_analysis(valid_files)
    
    print(f"Total Files: {preprocessing_result['file_count']}")
    print(f"Overall Valid: {preprocessing_result['is_valid']}")
    print(f"Primary Driver Type: {preprocessing_result['primary_driver_type'].value}")
    print(f"Average Complexity: {preprocessing_result['average_complexity']:.1f}")
    print(f"Total Lines: {preprocessing_result['total_lines']}")
    
    if preprocessing_result['detected_features']:
        print(f"All Detected Features: {', '.join(preprocessing_result['detected_features'])}")


if __name__ == "__main__":
    main()