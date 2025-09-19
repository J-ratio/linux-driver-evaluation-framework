"""
Tests for the Code Quality Analyzer.
"""

import unittest
import tempfile
import os
from unittest.mock import patch, MagicMock

from src.analyzers.code_quality_analyzer import (
    CodeQualityAnalyzer, 
    CodeQualityConfiguration, 
    CodeQualityCheckType
)
from src.core.interfaces import AnalysisStatus, Severity


class TestCodeQualityAnalyzer(unittest.TestCase):
    """Test cases for CodeQualityAnalyzer."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = CodeQualityAnalyzer()
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_analyzer_properties(self):
        """Test analyzer basic properties."""
        self.assertEqual(self.analyzer.name, "code_quality_analyzer")
        self.assertEqual(self.analyzer.version, "1.0.0")
    
    def test_validate_config_valid(self):
        """Test configuration validation with valid config."""
        valid_config = {
            'timeout': 300,
            'max_complexity': 10,
            'min_doc_coverage': 0.7
        }
        self.assertTrue(self.analyzer.validate_config(valid_config))
    
    def test_validate_config_invalid(self):
        """Test configuration validation with invalid config."""
        invalid_configs = [
            {'timeout': 'invalid'},  # Non-integer timeout
            {'max_complexity': -1},  # Negative complexity
            {'min_doc_coverage': 1.5}  # Coverage > 1.0
        ]
        
        for config in invalid_configs:
            with self.subTest(config=config):
                self.assertFalse(self.analyzer.validate_config(config))
    
    def test_extract_functions(self):
        """Test function extraction from C code."""
        c_code = '''
static int init_function(void) {
    return 0;
}

int public_function(int param) {
    if (param > 0) {
        return param * 2;
    }
    return -1;
}

static inline void inline_func(void) {
    // This should be ignored
}
'''
        
        functions = self.analyzer._extract_functions(c_code)
        
        # Should find init_function and public_function, but not inline_func
        self.assertIn('init_function', functions)
        self.assertIn('public_function', functions)
        self.assertEqual(len(functions), 2)
    
    def test_calculate_cyclomatic_complexity(self):
        """Test cyclomatic complexity calculation."""
        # Simple function with no branches (complexity = 1)
        simple_func = '''
    int x = 5;
    return x;
'''
        self.assertEqual(self.analyzer._calculate_cyclomatic_complexity(simple_func), 1)
        
        # Function with if statement (complexity = 2)
        if_func = '''
    if (x > 0) {
        return x;
    }
    return 0;
'''
        self.assertEqual(self.analyzer._calculate_cyclomatic_complexity(if_func), 2)
        
        # Function with multiple branches (complexity = 4)
        complex_func = '''
    if (x > 0) {
        if (y > 0) {
            return x + y;
        }
        return x;
    } else if (x < 0) {
        return -x;
    }
    return 0;
'''
        complexity = self.analyzer._calculate_cyclomatic_complexity(complex_func)
        self.assertGreaterEqual(complexity, 4)
    
    def test_find_functions_for_docs(self):
        """Test finding functions that need documentation."""
        c_code = '''
static inline void small_func(void) { }

int driver_probe(struct platform_device *pdev) {
    return 0;
}

static int helper_function(int param) {
    return param * 2;
}

static int init(void) {
    return 0;
}
'''
        
        functions = self.analyzer._find_functions_for_docs(c_code)
        
        # Should find driver_probe and helper_function, but not small_func or init
        self.assertIn('driver_probe', functions)
        self.assertIn('helper_function', functions)
        self.assertNotIn('init', functions)  # Common function name excluded
    
    def test_find_structs_for_docs(self):
        """Test finding structures that need documentation."""
        c_code = '''
struct device_data {
    int id;
    char name[32];
};

struct private_info {
    void *priv;
};
'''
        
        structs = self.analyzer._find_structs_for_docs(c_code)
        
        self.assertIn('device_data', structs)
        self.assertIn('private_info', structs)
        self.assertEqual(len(structs), 2)
    
    def test_has_documentation(self):
        """Test documentation detection."""
        # Code with proper kernel-doc
        documented_code = '''
/**
 * test_function - This is a test function
 * @param: Parameter description
 *
 * Return: 0 on success, negative on error
 */
int test_function(int param) {
    return 0;
}
'''
        
        # Find the function start
        func_start = documented_code.find('int test_function')
        self.assertTrue(self.analyzer._has_documentation(documented_code, func_start, 'function'))
        
        # Code without documentation
        undocumented_code = '''
int test_function(int param) {
    return 0;
}
'''
        
        func_start = undocumented_code.find('int test_function')
        self.assertFalse(self.analyzer._has_documentation(undocumented_code, func_start, 'function'))
    
    def test_get_complexity_severity(self):
        """Test complexity severity assignment."""
        self.assertEqual(self.analyzer._get_complexity_severity(5), Severity.LOW)
        self.assertEqual(self.analyzer._get_complexity_severity(12), Severity.MEDIUM)
        self.assertEqual(self.analyzer._get_complexity_severity(18), Severity.HIGH)
        self.assertEqual(self.analyzer._get_complexity_severity(25), Severity.CRITICAL)
    
    def test_analyze_empty_files(self):
        """Test analysis with no source files."""
        result = self.analyzer.analyze([], {})
        
        self.assertEqual(result.analyzer, "code_quality_analyzer")
        self.assertEqual(result.status, AnalysisStatus.FAILURE)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.score, 0.0)
    
    def test_analyze_nonexistent_files(self):
        """Test analysis with non-existent files."""
        result = self.analyzer.analyze(["/nonexistent/file.c"], {})
        
        self.assertEqual(result.analyzer, "code_quality_analyzer")
        self.assertEqual(result.status, AnalysisStatus.FAILURE)
        self.assertEqual(result.score, 0.0)
    
    def test_calculate_code_quality_score(self):
        """Test code quality score calculation."""
        from src.core.interfaces import Finding
        
        # No findings should give perfect score
        self.assertEqual(self.analyzer._calculate_code_quality_score([], {}), 100.0)
        
        # Critical finding should significantly reduce score
        critical_finding = Finding(
            type="test_critical",
            severity=Severity.CRITICAL,
            file="test.c",
            line=1,
            column=0,
            message="Critical issue",
            recommendation="Fix it"
        )
        
        score = self.analyzer._calculate_code_quality_score([critical_finding], {})
        self.assertLess(score, 90.0)
        
        # Multiple findings should reduce score further
        medium_finding = Finding(
            type="test_medium",
            severity=Severity.MEDIUM,
            file="test.c",
            line=2,
            column=0,
            message="Medium issue",
            recommendation="Fix it"
        )
        
        score_multiple = self.analyzer._calculate_code_quality_score([critical_finding, medium_finding], {})
        self.assertLess(score_multiple, score)
    
    def test_checkpatch_recommendation(self):
        """Test checkpatch recommendation generation."""
        recommendations = {
            'LONG_LINE': self.analyzer._get_checkpatch_recommendation('LONG_LINE'),
            'TRAILING_WHITESPACE': self.analyzer._get_checkpatch_recommendation('TRAILING_WHITESPACE'),
            'SPACING': self.analyzer._get_checkpatch_recommendation('SPACING'),
            'UNKNOWN_TYPE': self.analyzer._get_checkpatch_recommendation('UNKNOWN_TYPE')
        }
        
        # All recommendations should be non-empty strings
        for rec in recommendations.values():
            self.assertIsInstance(rec, str)
            self.assertGreater(len(rec), 0)
    
    def test_complexity_recommendation(self):
        """Test complexity recommendation generation."""
        recommendations = [
            self.analyzer._get_complexity_recommendation(8),
            self.analyzer._get_complexity_recommendation(12),
            self.analyzer._get_complexity_recommendation(18),
            self.analyzer._get_complexity_recommendation(25)
        ]
        
        # All recommendations should be non-empty strings
        for rec in recommendations:
            self.assertIsInstance(rec, str)
            self.assertGreater(len(rec), 0)


if __name__ == '__main__':
    unittest.main()