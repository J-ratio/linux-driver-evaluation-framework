"""
Tests for the correctness analyzer.
"""

import unittest
import tempfile
import os
from unittest.mock import patch, MagicMock

from src.analyzers.correctness_analyzer import CorrectnessAnalyzer, CorrectnessConfiguration, CorrectnessCheckType
from src.core.interfaces import AnalysisStatus, Severity


class TestCorrectnessAnalyzer(unittest.TestCase):
    """Test cases for the CorrectnessAnalyzer."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = CorrectnessAnalyzer()
        self.test_config = {
            'kernel_version': '5.15',
            'timeout': 60
        }
    
    def test_analyzer_properties(self):
        """Test analyzer name and version properties."""
        self.assertEqual(self.analyzer.name, "correctness_analyzer")
        self.assertEqual(self.analyzer.version, "1.0.0")
    
    def test_validate_config_no_docker(self):
        """Test config validation when Docker is not available."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = FileNotFoundError()
            result = self.analyzer.validate_config(self.test_config)
            self.assertFalse(result)
    
    def test_validate_config_docker_available(self):
        """Test config validation when Docker is available."""
        with patch('subprocess.run') as mock_run:
            # Mock successful Docker version check and tool availability
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_run.return_value = mock_result
            
            result = self.analyzer.validate_config(self.test_config)
            # Should pass if all tools are available
            self.assertTrue(result)
    
    def test_analyze_no_source_files(self):
        """Test analysis with no source files."""
        result = self.analyzer.analyze([], self.test_config)
        
        self.assertEqual(result.analyzer, "correctness_analyzer")
        self.assertEqual(result.status, AnalysisStatus.FAILURE)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].severity, Severity.CRITICAL)
        self.assertEqual(result.score, 0.0)
    
    def test_check_driver_patterns(self):
        """Test custom driver pattern checking."""
        # Test code with missing module_init
        test_code = """
#include <linux/module.h>
#include <linux/kernel.h>

static int __init test_init(void) {
    return 0;
}

static void __exit test_exit(void) {
    return;
}

// Missing module_init and module_exit declarations
MODULE_LICENSE("GPL");
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
            f.write(test_code)
            f.flush()
            
            try:
                findings = self.analyzer._check_driver_patterns(test_code, f.name)
                
                # Should find missing module_init and module_exit
                init_findings = [f for f in findings if f.type == "missing_module_init"]
                exit_findings = [f for f in findings if f.type == "missing_module_exit"]
                
                self.assertEqual(len(init_findings), 1)
                self.assertEqual(len(exit_findings), 1)
                self.assertEqual(init_findings[0].severity, Severity.CRITICAL)
                self.assertEqual(exit_findings[0].severity, Severity.CRITICAL)
                
            finally:
                os.unlink(f.name)
    
    def test_check_dangerous_functions(self):
        """Test detection of dangerous functions."""
        test_code = """
#include <linux/module.h>
#include <linux/string.h>

void test_function(char *dest, char *src) {
    strcpy(dest, src);  // Dangerous function
    sprintf(dest, "test %s", src);  // Another dangerous function
}
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
            f.write(test_code)
            f.flush()
            
            try:
                findings = self.analyzer._check_driver_patterns(test_code, f.name)
                
                dangerous_findings = [f for f in findings if f.type == "dangerous_function"]
                self.assertGreaterEqual(len(dangerous_findings), 2)  # Should find strcpy and sprintf
                
                for finding in dangerous_findings:
                    self.assertEqual(finding.severity, Severity.HIGH)
                
            finally:
                os.unlink(f.name)
    
    def test_check_input_validation(self):
        """Test input validation checking."""
        test_code = """
void test_function(int index, char *ptr) {
    char buffer[100];
    buffer[index] = 'x';  // Unchecked array access
    
    ptr->field = 10;  // Unchecked pointer dereference
}
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
            f.write(test_code)
            f.flush()
            
            try:
                findings = self.analyzer._check_input_validation(test_code, f.name)
                
                array_findings = [f for f in findings if f.type == "unchecked_array_access"]
                pointer_findings = [f for f in findings if f.type == "unchecked_pointer_dereference"]
                
                self.assertGreaterEqual(len(array_findings), 1)
                self.assertGreaterEqual(len(pointer_findings), 1)
                
            finally:
                os.unlink(f.name)
    
    def test_check_memory_safety(self):
        """Test memory safety checking."""
        test_code = """
void test_function(void) {
    char *buffer = kmalloc(100, GFP_KERNEL);
    // Missing kfree - should detect memory leak
    
    char *ptr = kmalloc(50, GFP_KERNEL);
    kfree(ptr);
    ptr->field = 10;  // Use after free
}
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
            f.write(test_code)
            f.flush()
            
            try:
                findings = self.analyzer._check_memory_safety(test_code, f.name)
                
                leak_findings = [f for f in findings if f.type == "memory_leak"]
                uaf_findings = [f for f in findings if f.type == "use_after_free"]
                
                self.assertGreaterEqual(len(leak_findings), 1)
                self.assertGreaterEqual(len(uaf_findings), 1)
                
                for finding in leak_findings:
                    self.assertEqual(finding.severity, Severity.HIGH)
                for finding in uaf_findings:
                    self.assertEqual(finding.severity, Severity.CRITICAL)
                
            finally:
                os.unlink(f.name)
    
    def test_calculate_correctness_score(self):
        """Test correctness score calculation."""
        from src.core.interfaces import Finding
        
        # Test with no findings
        score = self.analyzer._calculate_correctness_score([])
        self.assertEqual(score, 100.0)
        
        # Test with various severity findings
        findings = [
            Finding("test", Severity.CRITICAL, "test.c", 1, 1, "Critical issue", "Fix it"),
            Finding("test", Severity.HIGH, "test.c", 2, 1, "High issue", "Fix it"),
            Finding("test", Severity.MEDIUM, "test.c", 3, 1, "Medium issue", "Fix it"),
            Finding("test", Severity.LOW, "test.c", 4, 1, "Low issue", "Fix it")
        ]
        
        score = self.analyzer._calculate_correctness_score(findings)
        expected_deductions = 30.0 + 20.0 + 10.0 + 5.0  # 65.0
        expected_score = 100.0 - expected_deductions  # 35.0
        self.assertEqual(score, expected_score)
    
    def test_configuration_defaults(self):
        """Test default configuration values."""
        config = CorrectnessConfiguration(check_types=[CorrectnessCheckType.ALL])
        
        self.assertIsNotNone(config.clang_checkers)
        self.assertIsNotNone(config.coccinelle_rules)
        self.assertIsNotNone(config.custom_rules)
        self.assertEqual(config.timeout, 300)
        self.assertEqual(config.kernel_version, "5.15")


if __name__ == '__main__':
    unittest.main()