#!/usr/bin/env python3
"""
Demonstration of the correctness analyzer functionality.

This script shows how to use the CorrectnessAnalyzer to analyze Linux driver code
for correctness issues including semantic errors, API misuse, and common mistakes.
"""

import os
import sys
import tempfile
from pathlib import Path

# Add project root to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.analyzers.correctness_analyzer import CorrectnessAnalyzer, CorrectnessConfiguration, CorrectnessCheckType
from src.core.interfaces import Severity


def create_sample_driver_code():
    """Create sample driver code with various correctness issues."""
    
    # Good driver code example
    good_driver = """
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define DEVICE_NAME "sample_driver"
#define CLASS_NAME "sample"

static int major_number;
static struct class* sample_class = NULL;
static struct device* sample_device = NULL;

static int device_open(struct inode *inode, struct file *file);
static int device_release(struct inode *inode, struct file *file);
static ssize_t device_read(struct file *file, char *buffer, size_t len, loff_t *offset);
static ssize_t device_write(struct file *file, const char *buffer, size_t len, loff_t *offset);

static struct file_operations fops = {
    .open = device_open,
    .read = device_read,
    .write = device_write,
    .release = device_release,
};

static int __init sample_init(void) {
    printk(KERN_INFO "Sample: Initializing the Sample LKM\\n");
    
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        printk(KERN_ALERT "Sample failed to register a major number\\n");
        return major_number;
    }
    
    sample_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(sample_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        printk(KERN_ALERT "Failed to register device class\\n");
        return PTR_ERR(sample_class);
    }
    
    sample_device = device_create(sample_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(sample_device)) {
        class_destroy(sample_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        printk(KERN_ALERT "Failed to create the device\\n");
        return PTR_ERR(sample_device);
    }
    
    printk(KERN_INFO "Sample: device class created correctly\\n");
    return 0;
}

static void __exit sample_exit(void) {
    device_destroy(sample_class, MKDEV(major_number, 0));
    class_unregister(sample_class);
    class_destroy(sample_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    printk(KERN_INFO "Sample: Goodbye from the LKM!\\n");
}

static int device_open(struct inode *inode, struct file *file) {
    printk(KERN_INFO "Sample: Device has been opened\\n");
    return 0;
}

static int device_release(struct inode *inode, struct file *file) {
    printk(KERN_INFO "Sample: Device successfully closed\\n");
    return 0;
}

static ssize_t device_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {
    char *message = "Hello from kernel space!\\n";
    int message_len = strlen(message);
    int bytes_read = 0;
    
    if (*offset >= message_len)
        return 0;
    
    if (*offset + len > message_len)
        len = message_len - *offset;
    
    if (copy_to_user(buffer, message + *offset, len)) {
        return -EFAULT;
    }
    
    *offset += len;
    bytes_read = len;
    
    printk(KERN_INFO "Sample: Sent %d characters to the user\\n", bytes_read);
    return bytes_read;
}

static ssize_t device_write(struct file *filep, const char *buffer, size_t len, loff_t *offset) {
    char *kernel_buffer = kmalloc(len + 1, GFP_KERNEL);
    if (!kernel_buffer) {
        return -ENOMEM;
    }
    
    if (copy_from_user(kernel_buffer, buffer, len)) {
        kfree(kernel_buffer);
        return -EFAULT;
    }
    
    kernel_buffer[len] = '\\0';
    printk(KERN_INFO "Sample: Received %zu characters from the user\\n", len);
    
    kfree(kernel_buffer);
    return len;
}

module_init(sample_init);
module_exit(sample_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sample Author");
MODULE_DESCRIPTION("A sample Linux driver");
MODULE_VERSION("1.0");
"""
    
    # Problematic driver code with correctness issues
    problematic_driver = """
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define DEVICE_NAME "buggy_driver"

static int major_number;
static char *device_buffer;
static int buffer_size = 1024;

static int device_open(struct inode *inode, struct file *file);
static int device_release(struct inode *inode, struct file *file);
static ssize_t device_read(struct file *file, char *buffer, size_t len, loff_t *offset);
static ssize_t device_write(struct file *file, const char *buffer, size_t len, loff_t *offset);

static struct file_operations fops = {
    .open = device_open,
    .read = device_read,
    .write = device_write,
    .release = device_release,
};

static int __init buggy_init(void) {
    printk(KERN_INFO "Buggy: Initializing driver\\n");
    
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    // Missing error check for register_chrdev
    
    device_buffer = kmalloc(buffer_size, GFP_KERNEL);
    // Missing null check for kmalloc
    
    return 0;
}

static void __exit buggy_exit(void) {
    unregister_chrdev(major_number, DEVICE_NAME);
    // Missing kfree for device_buffer - memory leak
    printk(KERN_INFO "Buggy: Driver unloaded\\n");
}

static int device_open(struct inode *inode, struct file *file) {
    return 0;
}

static int device_release(struct inode *inode, struct file *file) {
    return 0;
}

static ssize_t device_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {
    int i;
    
    // Unchecked array access - potential buffer overflow
    for (i = 0; i < len; i++) {
        device_buffer[i] = 'A';
    }
    
    // Unchecked copy_to_user
    copy_to_user(buffer, device_buffer, len);
    
    return len;
}

static ssize_t device_write(struct file *filep, const char *buffer, size_t len, loff_t *offset) {
    char temp_buffer[100];
    
    // Dangerous strcpy usage
    strcpy(temp_buffer, "prefix: ");
    
    // Unchecked copy_from_user
    copy_from_user(device_buffer, buffer, len);
    
    // Use after potential free (simulated)
    kfree(device_buffer);
    device_buffer[0] = 'X';  // Use after free
    
    return len;
}

// Missing module_init and module_exit declarations
// Missing MODULE_LICENSE
"""
    
    return good_driver, problematic_driver


def analyze_driver_code(analyzer, code, filename):
    """Analyze driver code and print results."""
    print(f"\n{'='*60}")
    print(f"Analyzing: {filename}")
    print(f"{'='*60}")
    
    # Create temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
        f.write(code)
        f.flush()
        
        try:
            # Run analysis
            result = analyzer.analyze([f.name], {})
            
            print(f"Analysis Status: {result.status.value}")
            print(f"Overall Score: {result.score:.1f}/100.0")
            print(f"Total Findings: {len(result.findings)}")
            
            if result.findings:
                print(f"\nFindings by Severity:")
                severity_counts = {}
                for finding in result.findings:
                    severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
                
                for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
                    count = severity_counts.get(severity, 0)
                    if count > 0:
                        print(f"  {severity.value.upper()}: {count}")
                
                print(f"\nDetailed Findings:")
                for i, finding in enumerate(result.findings, 1):
                    print(f"\n{i}. {finding.type} ({finding.severity.value})")
                    print(f"   File: {finding.file}, Line: {finding.line}")
                    print(f"   Message: {finding.message}")
                    print(f"   Recommendation: {finding.recommendation}")
            
            print(f"\nMetrics:")
            for key, value in result.metrics.items():
                if isinstance(value, (int, float)):
                    print(f"  {key}: {value}")
                elif isinstance(value, list):
                    print(f"  {key}: {', '.join(map(str, value))}")
                else:
                    print(f"  {key}: {value}")
                    
        finally:
            os.unlink(f.name)


def main():
    """Main demonstration function."""
    print("Linux Driver Correctness Analyzer Demo")
    print("=" * 50)
    
    # Create analyzer with custom configuration
    config = CorrectnessConfiguration(
        check_types=[CorrectnessCheckType.CUSTOM_VALIDATION],  # Only run custom validation for demo
        timeout=60,
        kernel_version="5.15"
    )
    
    analyzer = CorrectnessAnalyzer(config)
    
    print(f"Analyzer: {analyzer.name} v{analyzer.version}")
    print(f"Configuration: {[ct.value for ct in config.check_types]}")
    
    # Create sample code
    good_driver, problematic_driver = create_sample_driver_code()
    
    # Analyze good driver code
    analyze_driver_code(analyzer, good_driver, "good_driver.c")
    
    # Analyze problematic driver code
    analyze_driver_code(analyzer, problematic_driver, "problematic_driver.c")
    
    print(f"\n{'='*60}")
    print("Demo completed!")
    print("Note: This demo only runs custom validation rules.")
    print("Full analysis requires Docker with clang and Coccinelle tools.")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()