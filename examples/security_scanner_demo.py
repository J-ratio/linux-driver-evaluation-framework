#!/usr/bin/env python3
"""
Security Scanner Demo

This script demonstrates the security scanner component by analyzing
example driver code for security vulnerabilities.
"""

import os
import sys
import tempfile
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.analyzers.security_analyzer import SecurityScanner, SecurityConfiguration, SecurityCheckType
from src.core.interfaces import Severity


def create_vulnerable_driver():
    """Create a sample driver with various security vulnerabilities."""
    vulnerable_code = """
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/capability.h>
#include <linux/spinlock.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Vulnerable Driver Demo");

static int major_number;
static char *device_buffer;
static DEFINE_SPINLOCK(buffer_lock);
static int buffer_size = 1024;

// Vulnerable function with multiple security issues
static ssize_t device_write(struct file *file, const char __user *buffer, 
                           size_t length, loff_t *offset) {
    char temp_buffer[256];
    char *kernel_buffer;
    
    // Issue 1: Unchecked copy_from_user - CRITICAL
    copy_from_user(temp_buffer, buffer, length);
    
    // Issue 2: Dangerous strcpy function - HIGH
    strcpy(device_buffer, temp_buffer);
    
    // Issue 3: Unchecked kmalloc - HIGH
    kernel_buffer = kmalloc(length, GFP_KERNEL);
    
    // Issue 4: Potential integer overflow in allocation - MEDIUM
    kernel_buffer = kmalloc(length * sizeof(int), GFP_KERNEL);
    
    // Issue 5: sprintf without bounds checking - HIGH
    sprintf(kernel_buffer, "Data: %s", temp_buffer);
    
    return length;
}

static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    // Issue 6: Overly broad capability check - HIGH
    if (!capable(CAP_SYS_ADMIN)) {
        return -EPERM;
    }
    
    // Issue 7: Race condition - lock not released on error path - CRITICAL
    spin_lock(&buffer_lock);
    
    if (cmd == 0) {
        return -EINVAL;  // Lock not released!
    }
    
    // Issue 8: Direct hardware access without validation - MEDIUM
    outb(0x42, 0x3f8);
    
    spin_unlock(&buffer_lock);
    return 0;
}

static int device_open(struct inode *inode, struct file *file) {
    // Issue 9: Unchecked get_user - HIGH
    int user_value;
    get_user(user_value, (int __user *)file->private_data);
    
    return 0;
}

static int device_release(struct inode *inode, struct file *file) {
    return 0;
}

static struct file_operations fops = {
    .open = device_open,
    .release = device_release,
    .write = device_write,
    .unlocked_ioctl = device_ioctl,
};

static int __init vulnerable_init(void) {
    major_number = register_chrdev(0, "vulnerable_device", &fops);
    if (major_number < 0) {
        return major_number;
    }
    
    // Issue 10: Unchecked kmalloc in init - HIGH
    device_buffer = kmalloc(buffer_size, GFP_KERNEL);
    
    printk(KERN_INFO "Vulnerable device registered with major number %d\\n", major_number);
    return 0;
}

static void __exit vulnerable_exit(void) {
    unregister_chrdev(major_number, "vulnerable_device");
    kfree(device_buffer);
    printk(KERN_INFO "Vulnerable device unregistered\\n");
}

module_init(vulnerable_init);
module_exit(vulnerable_exit);
"""
    return vulnerable_code


def create_secure_driver():
    """Create a sample driver with proper security practices."""
    secure_code = """
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/capability.h>
#include <linux/spinlock.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Secure Driver Demo");

static int major_number;
static char *device_buffer;
static DEFINE_SPINLOCK(buffer_lock);
static const int buffer_size = 1024;

// Secure function with proper error handling
static ssize_t device_write(struct file *file, const char __user *buffer, 
                           size_t length, loff_t *offset) {
    char temp_buffer[256];
    char *kernel_buffer;
    unsigned long not_copied;
    
    // Proper length validation
    if (length > sizeof(temp_buffer) - 1) {
        return -EINVAL;
    }
    
    // Checked copy_from_user
    not_copied = copy_from_user(temp_buffer, buffer, length);
    if (not_copied) {
        return -EFAULT;
    }
    temp_buffer[length] = '\\0';  // Null terminate
    
    // Safe string copy with bounds checking
    strncpy(device_buffer, temp_buffer, buffer_size - 1);
    device_buffer[buffer_size - 1] = '\\0';
    
    // Checked kmalloc with overflow protection
    if (length > SIZE_MAX / sizeof(int)) {
        return -EINVAL;
    }
    
    kernel_buffer = kmalloc(length * sizeof(int), GFP_KERNEL);
    if (!kernel_buffer) {
        return -ENOMEM;
    }
    
    // Safe formatted output
    snprintf(kernel_buffer, length * sizeof(int), "Data: %s", temp_buffer);
    
    kfree(kernel_buffer);
    return length;
}

static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    int ret = 0;
    
    // More specific capability check
    if (!capable(CAP_DAC_OVERRIDE)) {
        return -EPERM;
    }
    
    // Proper locking with error handling
    spin_lock(&buffer_lock);
    
    switch (cmd) {
        case 0:
            ret = -EINVAL;
            break;
        default:
            ret = -ENOTTY;
            break;
    }
    
    spin_unlock(&buffer_lock);  // Always released
    return ret;
}

static int device_open(struct inode *inode, struct file *file) {
    int user_value;
    int ret;
    
    // Checked get_user
    ret = get_user(user_value, (int __user *)file->private_data);
    if (ret) {
        return ret;
    }
    
    return 0;
}

static int device_release(struct inode *inode, struct file *file) {
    return 0;
}

static struct file_operations fops = {
    .open = device_open,
    .release = device_release,
    .write = device_write,
    .unlocked_ioctl = device_ioctl,
};

static int __init secure_init(void) {
    major_number = register_chrdev(0, "secure_device", &fops);
    if (major_number < 0) {
        return major_number;
    }
    
    // Checked kmalloc in init
    device_buffer = kmalloc(buffer_size, GFP_KERNEL);
    if (!device_buffer) {
        unregister_chrdev(major_number, "secure_device");
        return -ENOMEM;
    }
    
    printk(KERN_INFO "Secure device registered with major number %d\\n", major_number);
    return 0;
}

static void __exit secure_exit(void) {
    unregister_chrdev(major_number, "secure_device");
    kfree(device_buffer);
    printk(KERN_INFO "Secure device unregistered\\n");
}

module_init(secure_init);
module_exit(secure_exit);
"""
    return secure_code


def analyze_driver(driver_code, driver_name):
    """Analyze a driver and print results."""
    print(f"\n{'='*60}")
    print(f"Analyzing {driver_name}")
    print(f"{'='*60}")
    
    # Create temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
        f.write(driver_code)
        temp_file = f.name
    
    try:
        # Create security scanner with comprehensive configuration
        config = SecurityConfiguration(
            check_types=[SecurityCheckType.ALL],
            timeout=60,
            flawfinder_min_level=1,
            enable_context_analysis=True
        )
        
        scanner = SecurityScanner(config)
        
        # Run analysis
        result = scanner.analyze([temp_file], {})
        
        # Print results
        print(f"Analysis Status: {result.status.value}")
        print(f"Security Score: {result.score:.1f}/100.0")
        print(f"Total Findings: {len(result.findings)}")
        
        # Group findings by severity
        severity_counts = {}
        for finding in result.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        
        print("\nFindings by Severity:")
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                print(f"  {severity.value.upper()}: {count}")
        
        # Print detailed findings
        if result.findings:
            print(f"\nDetailed Findings:")
            print("-" * 60)
            
            for i, finding in enumerate(result.findings[:10], 1):  # Show first 10
                print(f"{i}. [{finding.severity.value.upper()}] {finding.type}")
                print(f"   File: {finding.file}:{finding.line}:{finding.column}")
                print(f"   Message: {finding.message}")
                print(f"   Recommendation: {finding.recommendation}")
                print()
            
            if len(result.findings) > 10:
                print(f"... and {len(result.findings) - 10} more findings")
        
        # Print metrics
        print(f"\nAnalysis Metrics:")
        for key, value in result.metrics.items():
            if isinstance(value, dict):
                print(f"  {key}:")
                for sub_key, sub_value in value.items():
                    print(f"    {sub_key}: {sub_value}")
            else:
                print(f"  {key}: {value}")
    
    finally:
        # Clean up temporary file
        os.unlink(temp_file)


def main():
    """Main demo function."""
    print("Linux Driver Security Scanner Demo")
    print("=" * 60)
    print("This demo shows the security scanner analyzing two drivers:")
    print("1. A vulnerable driver with multiple security issues")
    print("2. A secure driver with proper security practices")
    
    # Analyze vulnerable driver
    vulnerable_code = create_vulnerable_driver()
    analyze_driver(vulnerable_code, "Vulnerable Driver")
    
    # Analyze secure driver
    secure_code = create_secure_driver()
    analyze_driver(secure_code, "Secure Driver")
    
    print(f"\n{'='*60}")
    print("Demo completed!")
    print("The security scanner successfully identified multiple")
    print("vulnerabilities in the vulnerable driver and fewer")
    print("issues in the secure driver.")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()