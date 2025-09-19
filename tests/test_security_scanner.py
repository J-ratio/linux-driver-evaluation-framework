"""
Tests for the security scanner component.
"""

import unittest
import tempfile
import os
from unittest.mock import patch, MagicMock

from src.analyzers.security_analyzer import SecurityScanner, SecurityConfiguration, SecurityCheckType
from src.core.interfaces import AnalysisStatus, Severity


class TestSecurityScanner(unittest.TestCase):
    """Test cases for SecurityScanner."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.scanner = SecurityScanner()
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_scanner_properties(self):
        """Test scanner basic properties."""
        self.assertEqual(self.scanner.name, "security_analyzer")
        self.assertEqual(self.scanner.version, "1.0.0")
    
    def test_validate_config_valid(self):
        """Test configuration validation with valid config."""
        valid_config = {
            'timeout': 300,
            'flawfinder_min_level': 2
        }
        self.assertTrue(self.scanner.validate_config(valid_config))
    
    def test_validate_config_invalid(self):
        """Test configuration validation with invalid config."""
        invalid_config = {
            'timeout': 'invalid',
            'flawfinder_min_level': 10  # Out of range
        }
        self.assertFalse(self.scanner.validate_config(invalid_config))
    
    def test_dangerous_function_detection(self):
        """Test detection of dangerous functions."""
        # Create test file with dangerous function
        test_content = """
#include <linux/module.h>
#include <linux/kernel.h>

static int test_function(char *input) {
    char buffer[100];
    strcpy(buffer, input);  // Dangerous function
    return 0;
}
"""
        test_file = os.path.join(self.temp_dir, "test_driver.c")
        with open(test_file, 'w') as f:
            f.write(test_content)
        
        # Run analysis
        result = self.scanner.analyze([test_file], {})
        
        # Check results
        self.assertIsNotNone(result)
        self.assertTrue(any('strcpy' in f.type for f in result.findings))
        
        # Find the strcpy finding
        strcpy_finding = next(f for f in result.findings if 'strcpy' in f.type)
        self.assertEqual(strcpy_finding.severity, Severity.HIGH)
        self.assertIn('buffer overflow', strcpy_finding.message.lower())
    
    def test_kernel_security_pattern_detection(self):
        """Test detection of kernel security patterns."""
        # Create test file with unchecked copy_from_user
        test_content = """
#include <linux/module.h>
#include <linux/uaccess.h>

static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    char buffer[100];
    copy_from_user(buffer, (void __user *)arg, 100);  // Unchecked
    return 0;
}
"""
        test_file = os.path.join(self.temp_dir, "test_driver.c")
        with open(test_file, 'w') as f:
            f.write(test_content)
        
        # Run analysis
        result = self.scanner.analyze([test_file], {})
        
        # Check results
        self.assertIsNotNone(result)
        self.assertTrue(any('copy_from_user' in f.type for f in result.findings))
        
        # Find the copy_from_user finding
        copy_finding = next(f for f in result.findings if 'copy_from_user' in f.type)
        self.assertEqual(copy_finding.severity, Severity.CRITICAL)
    
    def test_race_condition_detection(self):
        """Test detection of race conditions."""
        # Create test file with potential race condition
        test_content = """
#include <linux/module.h>
#include <linux/spinlock.h>

static DEFINE_SPINLOCK(test_lock);
static int global_counter = 0;

static int test_function(void) {
    spin_lock(&test_lock);
    global_counter++;
    if (global_counter > 100) {
        return -EINVAL;  // Lock not released!
    }
    spin_unlock(&test_lock);
    return 0;
}
"""
        test_file = os.path.join(self.temp_dir, "test_driver.c")
        with open(test_file, 'w') as f:
            f.write(test_content)
        
        # Run analysis
        result = self.scanner.analyze([test_file], {})
        
        # Check results
        self.assertIsNotNone(result)
        self.assertTrue(any('lock' in f.type for f in result.findings))
    
    def test_privilege_escalation_detection(self):
        """Test detection of privilege escalation patterns."""
        # Create test file with capability usage
        test_content = """
#include <linux/module.h>
#include <linux/capability.h>

static int test_function(void) {
    if (!capable(CAP_SYS_ADMIN)) {
        return -EPERM;
    }
    return 0;
}
"""
        test_file = os.path.join(self.temp_dir, "test_driver.c")
        with open(test_file, 'w') as f:
            f.write(test_content)
        
        # Run analysis
        result = self.scanner.analyze([test_file], {})
        
        # Check results
        self.assertIsNotNone(result)
        self.assertTrue(any('privilege' in f.type for f in result.findings))
    
    def test_empty_source_files(self):
        """Test handling of empty source files list."""
        result = self.scanner.analyze([], {})
        
        self.assertEqual(result.status, AnalysisStatus.FAILURE)
        self.assertEqual(result.score, 0.0)
        self.assertTrue(any('No valid source files' in f.message for f in result.findings))
    
    def test_nonexistent_source_files(self):
        """Test handling of nonexistent source files."""
        result = self.scanner.analyze(['/nonexistent/file.c'], {})
        
        self.assertEqual(result.status, AnalysisStatus.FAILURE)
        self.assertEqual(result.score, 0.0)
    
    def test_security_score_calculation(self):
        """Test security score calculation."""
        # Test with no findings (perfect score)
        score = self.scanner._calculate_security_score([])
        self.assertEqual(score, 100.0)
        
        # Test with mock findings
        from src.core.interfaces import Finding
        findings = [
            Finding("test", Severity.CRITICAL, "test.c", 1, 1, "Critical issue", "Fix it"),
            Finding("test", Severity.HIGH, "test.c", 2, 1, "High issue", "Fix it"),
            Finding("test", Severity.MEDIUM, "test.c", 3, 1, "Medium issue", "Fix it")
        ]
        
        score = self.scanner._calculate_security_score(findings)
        self.assertLess(score, 100.0)
        self.assertGreaterEqual(score, 0.0)
    
    def test_security_configuration(self):
        """Test security configuration."""
        config = SecurityConfiguration(
            check_types=[SecurityCheckType.FLAWFINDER],
            timeout=600,
            flawfinder_min_level=3
        )
        
        scanner = SecurityScanner(config)
        self.assertEqual(scanner.config.timeout, 600)
        self.assertEqual(scanner.config.flawfinder_min_level, 3)
        self.assertEqual(len(scanner.config.check_types), 1)
    
    @patch('subprocess.run')
    def test_flawfinder_integration(self, mock_run):
        """Test Flawfinder integration."""
        # Mock flawfinder output
        mock_run.return_value.stdout = "test.c:10:5: [3] (buffer) strcpy: Does not check for buffer overflows"
        mock_run.return_value.stderr = ""
        mock_run.return_value.returncode = 0
        
        # Create test file
        test_file = os.path.join(self.temp_dir, "test.c")
        with open(test_file, 'w') as f:
            f.write("int main() { return 0; }")
        
        # Run analysis with only flawfinder
        config = SecurityConfiguration(check_types=[SecurityCheckType.FLAWFINDER])
        scanner = SecurityScanner(config)
        
        result = scanner.analyze([test_file], {})
        
        # Verify flawfinder was called
        mock_run.assert_called()
        self.assertIsNotNone(result)


if __name__ == '__main__':
    unittest.main()