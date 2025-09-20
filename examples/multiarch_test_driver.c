/*
 * Multi-Architecture Test Driver
 * 
 * This driver demonstrates cross-platform compatibility
 * and can be compiled for x86_64, ARM64, and RISC-V.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>

static int __init multiarch_init(void)
{
    printk(KERN_INFO "Multi-Architecture Test Driver Loading...\n");
    
    #ifdef CONFIG_X86_64
    printk(KERN_INFO "Running on x86_64 architecture\n");
    #elif defined(CONFIG_ARM64)
    printk(KERN_INFO "Running on ARM64 architecture\n");
    #elif defined(CONFIG_RISCV)
    printk(KERN_INFO "Running on RISC-V architecture\n");
    #else
    printk(KERN_INFO "Running on unknown architecture\n");
    #endif
    
    printk(KERN_INFO "Driver loaded successfully\n");
    return 0;
}

static void __exit multiarch_exit(void)
{
    printk(KERN_INFO "Multi-Architecture Test Driver Unloading...\n");
    printk(KERN_INFO "Driver unloaded successfully\n");
}

module_init(multiarch_init);
module_exit(multiarch_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Driver Evaluation Framework");
MODULE_DESCRIPTION("Multi-architecture test driver");
MODULE_VERSION("1.0");
