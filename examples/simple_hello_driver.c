/*
 * Simple Hello World Linux Kernel Module
 * 
 * A minimal kernel module that demonstrates basic module loading/unloading.
 * This is the simplest possible Linux driver example.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

/**
 * hello_init - Module initialization function
 * 
 * Called when the module is loaded into the kernel.
 * 
 * Return: 0 on success
 */
static int __init hello_init(void)
{
    printk(KERN_INFO "Hello World: Module loaded successfully\n");
    printk(KERN_INFO "Hello World: Welcome to Linux kernel development!\n");
    return 0;
}

/**
 * hello_exit - Module cleanup function
 * 
 * Called when the module is removed from the kernel.
 */
static void __exit hello_exit(void)
{
    printk(KERN_INFO "Hello World: Module unloaded successfully\n");
    printk(KERN_INFO "Hello World: Goodbye from kernel space!\n");
}

/* Register module entry and exit points */
module_init(hello_init);
module_exit(hello_exit);

/* Module metadata */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Driver Evaluation Framework");
MODULE_DESCRIPTION("A simple hello world kernel module");
MODULE_VERSION("1.0");
MODULE_ALIAS("hello_world");