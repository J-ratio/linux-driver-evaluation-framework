"""
Unit tests for the input validation and preprocessing services.
"""

import unittest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from models.evaluation import SourceFile
from services.validation import (
    InputValidator, CSourceValidator, LinuxDriverDetector,
    DriverType, ValidationResult
)


class TestCSourceValidator(unittest.TestCase):
    """Test cases for C source code validation."""
    
    def setUp(self):
        """Set up test data."""
        self.validator = CSourceValidator()
    
    def test_valid_c_code(self):
        """Test validation of valid C code."""
        content = """
        #include <stdio.h>
        
        int main() {
            printf("Hello, World!");
            return 0;
        }
        """
        
        is_valid, errors, warnings = self.validator.validate_syntax(content)
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)
    
    def test_unmatched_braces(self):
        """Test detection of unmatched braces."""
        content = """
        int main() {
            printf("Hello");
        // Missing closing brace
        """
        
        is_valid, errors, warnings = self.validator.validate_syntax(content)
        self.assertFalse(is_valid)
        self.assertTrue(any("Unmatched opening braces" in error for error in errors))
    
    def test_dangerous_functions(self):
        """Test detection of dangerous functions."""
        content = """
        #include <string.h>
        
        void test() {
            char buf[10];
            strcpy(buf, "dangerous");
        }
        """
        
        is_valid, errors, warnings = self.validator.validate_syntax(content)
        self.assertTrue(any("Dangerous function 'strcpy'" in warning for warning in warnings))
    
    def test_no_functions(self):
        """Test warning for code with no functions."""
        content = """
        #include <stdio.h>
        int global_var = 5;
        """
        
        is_valid, errors, warnings = self.validator.validate_syntax(content)
        self.assertTrue(any("No function definitions found" in warning for warning in warnings))


class TestLinuxDriverDetector(unittest.TestCase):
    """Test cases for Linux driver detection."""
    
    def setUp(self):
        """Set up test data."""
        self.detector = LinuxDriverDetector()
    
    def test_character_device_detection(self):
        """Test detection of character device driver."""
        content = """
        #include <linux/module.h>
        #include <linux/fs.h>
        #include <linux/cdev.h>
        
        static struct file_operations fops = {
            .open = device_open,
            .release = device_release,
            .read = device_read,
            .write = device_write,
        };
        
        static int __init char_driver_init(void) {
            register_chrdev(MAJOR_NUM, DEVICE_NAME, &fops);
            return 0;
        }
        
        module_init(char_driver_init);
        MODULE_LICENSE("GPL");
        """
        
        driver_type = self.detector.detect_driver_type(content)
        self.assertEqual(driver_type, DriverType.CHARACTER_DEVICE)
    
    def test_network_device_detection(self):
        """Test detection of network device driver."""
        content = """
        #include <linux/module.h>
        #include <linux/netdevice.h>
        
        static struct net_device *dev;
        
        static int __init net_driver_init(void) {
            dev = alloc_netdev(0, "mynet%d", NET_NAME_UNKNOWN, setup);
            register_netdev(dev);
            return 0;
        }
        
        module_init(net_driver_init);
        MODULE_LICENSE("GPL");
        """
        
        driver_type = self.detector.detect_driver_type(content)
        self.assertEqual(driver_type, DriverType.NETWORK_DEVICE)
    
    def test_generic_module_detection(self):
        """Test detection of generic kernel module."""
        content = """
        #include <linux/module.h>
        #include <linux/kernel.h>
        
        static int __init hello_init(void) {
            printk(KERN_INFO "Hello, World!\\n");
            return 0;
        }
        
        static void __exit hello_exit(void) {
            printk(KERN_INFO "Goodbye, World!\\n");
        }
        
        module_init(hello_init);
        module_exit(hello_exit);
        MODULE_LICENSE("GPL");
        """
        
        driver_type = self.detector.detect_driver_type(content)
        self.assertEqual(driver_type, DriverType.GENERIC_MODULE)
    
    def test_unknown_code_detection(self):
        """Test detection of non-driver code."""
        content = """
        #include <stdio.h>
        
        int main() {
            printf("This is not a driver\\n");
            return 0;
        }
        """
        
        driver_type = self.detector.detect_driver_type(content)
        self.assertEqual(driver_type, DriverType.UNKNOWN)
    
    def test_feature_detection(self):
        """Test detection of advanced features."""
        content = """
        #include <linux/module.h>
        #include <linux/of.h>
        #include <linux/pm.h>
        #include <linux/interrupt.h>
        
        static int driver_suspend(struct device *dev) {
            return 0;
        }
        
        static int driver_resume(struct device *dev) {
            return 0;
        }
        
        static irqreturn_t driver_irq_handler(int irq, void *dev_id) {
            return IRQ_HANDLED;
        }
        
        static int driver_probe(struct platform_device *pdev) {
            request_irq(irq, driver_irq_handler, 0, "driver", NULL);
            of_property_read_u32(pdev->dev.of_node, "reg", &reg);
            return 0;
        }
        
        MODULE_LICENSE("GPL");
        """
        
        features = self.detector.detect_features(content)
        
        # Check for expected features
        self.assertIn('basic_module', features)
        self.assertIn('device_tree', features)
        self.assertIn('power_management', features)
        self.assertIn('interrupt_handling', features)
    
    def test_complexity_calculation(self):
        """Test complexity score calculation."""
        simple_content = """
        #include <linux/module.h>
        
        static int __init simple_init(void) {
            return 0;
        }
        
        module_init(simple_init);
        MODULE_LICENSE("GPL");
        """
        
        complex_content = """
        #include <linux/module.h>
        #include <linux/fs.h>
        
        struct my_device {
            int id;
            char name[32];
            struct cdev cdev;
        };
        
        static int device_open(struct inode *inode, struct file *file) {
            if (condition1) {
                for (int i = 0; i < 10; i++) {
                    if (condition2) {
                        switch (value) {
                            case 1:
                                break;
                            case 2:
                                break;
                            default:
                                break;
                        }
                    }
                }
            }
            return 0;
        }
        
        static int device_release(struct inode *inode, struct file *file) {
            return 0;
        }
        
        static ssize_t device_read(struct file *file, char __user *buffer, size_t length, loff_t *offset) {
            return 0;
        }
        
        MODULE_LICENSE("GPL");
        """
        
        simple_score = self.detector.calculate_complexity(simple_content)
        complex_score = self.detector.calculate_complexity(complex_content)
        
        self.assertGreater(complex_score, simple_score)
        self.assertGreaterEqual(simple_score, 0)
        self.assertLessEqual(complex_score, 100)


class TestInputValidator(unittest.TestCase):
    """Test cases for the main input validator."""
    
    def setUp(self):
        """Set up test data."""
        self.validator = InputValidator()
    
    def test_valid_driver_file(self):
        """Test validation of a valid driver file."""
        content = """
        #include <linux/module.h>
        #include <linux/fs.h>
        #include <linux/cdev.h>
        
        static struct file_operations fops = {
            .open = device_open,
            .release = device_release,
        };
        
        static int __init driver_init(void) {
            register_chrdev(240, "mydevice", &fops);
            return 0;
        }
        
        static void __exit driver_exit(void) {
            unregister_chrdev(240, "mydevice");
        }
        
        module_init(driver_init);
        module_exit(driver_exit);
        MODULE_LICENSE("GPL");
        """
        
        source_file = SourceFile(
            filename="test_driver.c",
            content=content,
            size=len(content)
        )
        
        result = self.validator.validate_source_file(source_file)
        
        self.assertTrue(result.is_valid)
        self.assertEqual(result.driver_type, DriverType.CHARACTER_DEVICE)
        self.assertIn('basic_module', result.detected_features)
        self.assertGreater(result.complexity_score, 0)
    
    def test_invalid_file_extension(self):
        """Test validation with invalid file extension."""
        source_file = SourceFile(
            filename="test.txt",
            content="some content",
            size=12
        )
        
        result = self.validator.validate_source_file(source_file)
        
        self.assertFalse(result.is_valid)
        self.assertIn("File must have .c extension", result.errors)
    
    def test_non_driver_code(self):
        """Test validation of non-driver C code."""
        content = """
        #include <stdio.h>
        
        int main() {
            printf("Hello, World!\\n");
            return 0;
        }
        """
        
        source_file = SourceFile(
            filename="hello.c",
            content=content,
            size=len(content)
        )
        
        result = self.validator.validate_source_file(source_file)
        
        # Should be valid C but not driver code
        self.assertTrue(result.is_valid)
        self.assertEqual(result.driver_type, DriverType.UNKNOWN)
        self.assertIn("Code does not appear to contain Linux driver patterns", result.warnings)
    
    def test_syntax_errors(self):
        """Test validation with C syntax errors."""
        content = """
        #include <linux/module.h>
        
        static int __init driver_init(void) {
            // Missing closing brace
            return 0;
        
        MODULE_LICENSE("GPL");
        """
        
        source_file = SourceFile(
            filename="bad_driver.c",
            content=content,
            size=len(content)
        )
        
        result = self.validator.validate_source_file(source_file)
        
        self.assertFalse(result.is_valid)
        self.assertTrue(any("Unmatched opening braces" in error for error in result.errors))
    
    def test_multiple_files_preprocessing(self):
        """Test preprocessing of multiple source files."""
        content1 = """
        #include <linux/module.h>
        #include <linux/fs.h>
        
        static int __init driver1_init(void) {
            return 0;
        }
        
        MODULE_LICENSE("GPL");
        """
        
        content2 = """
        #include <linux/module.h>
        #include <linux/netdevice.h>
        
        static struct net_device *dev;
        
        static int __init driver2_init(void) {
            dev = alloc_netdev(0, "net%d", NET_NAME_UNKNOWN, setup);
            return 0;
        }
        
        MODULE_LICENSE("GPL");
        """
        
        source_files = [
            SourceFile("driver1.c", content1, len(content1)),
            SourceFile("driver2.c", content2, len(content2))
        ]
        
        preprocessing_result = self.validator.preprocess_for_analysis(source_files)
        
        self.assertTrue(preprocessing_result['is_valid'])
        self.assertEqual(preprocessing_result['file_count'], 2)
        self.assertIn('basic_module', preprocessing_result['detected_features'])
        self.assertGreater(preprocessing_result['average_complexity'], 0)
        self.assertGreater(preprocessing_result['total_lines'], 0)
    
    def test_empty_file_list(self):
        """Test preprocessing with empty file list."""
        preprocessing_result = self.validator.preprocess_for_analysis([])
        
        self.assertTrue(preprocessing_result['is_valid'])  # No errors with empty list
        self.assertEqual(preprocessing_result['file_count'], 0)
        self.assertEqual(preprocessing_result['average_complexity'], 0)


if __name__ == '__main__':
    unittest.main()