
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>

static char *buffer;
static int __init test_init(void)
{
    char __user *user_ptr;
    char *kernel_ptr;
    
    // Address space issue - should trigger sparse warning
    kernel_ptr = user_ptr;  // Different address spaces
    
    // Endianness issue
    __be32 big_endian = 0x12345678;
    u32 native = big_endian;  // Should use be32_to_cpu()
    
    // Potential null pointer dereference
    if (buffer)
        *buffer = 'x';  // Should check buffer first
    
    return 0;
}

static void __exit test_exit(void)
{
    // Empty cleanup
}

module_init(test_init);
module_exit(test_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Test driver with sparse issues");
