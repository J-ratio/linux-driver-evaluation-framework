#!/usr/bin/env python3
"""
Unit tests for the Performance Analyzer.

This module tests the performance analysis functionality including
algorithmic complexity analysis, memory allocation pattern detection,
and I/O efficiency analysis.
"""

import unittest
import tempfile
import os
from typing import List

from src.analyzers.performance_analyzer import PerformanceAnalyzer, PerformanceConfiguration, PerformanceCheckType
from src.core.interfaces import AnalysisStatus, Severity


class TestPerformanceAnalyzer(unittest.TestCase):
    """Test cases for PerformanceAnalyzer."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = PerformanceAnalyzer()
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures."""
        # Clean up temp directory
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def _create_test_file(self, filename: str, content: str) -> str:
        """Create a test file with given content."""
        filepath = os.path.join(self.temp_dir, filename)
        with open(filepath, 'w') as f:
            f.write(content)
        return filepath
    
    def test_analyzer_properties(self):
        """Test analyzer basic properties."""
        self.assertEqual(self.analyzer.name, "performance_analyzer")
        self.assertEqual(self.analyzer.version, "1.0.0")
    
    def test_config_validation(self):
        """Test configuration validation."""
        # Valid config
        valid_config = {
            'timeout': 300,
            'max_complexity_threshold': 15,
            'memory_efficiency_threshold': 0.7,
            'io_efficiency_threshold': 0.6
        }
        self.assertTrue(self.analyzer.validate_config(valid_config))
        
        # Invalid timeout
        invalid_config = {'timeout': 'invalid'}
        self.assertFalse(self.analyzer.validate_config(invalid_config))
        
        # Invalid threshold
        invalid_config = {'max_complexity_threshold': -1}
        self.assertFalse(self.analyzer.validate_config(invalid_config))
    
    def test_algorithmic_complexity_analysis(self):
        """Test algorithmic complexity analysis."""
        # High complexity function with nested loops
        high_complexity_code = '''
static int complex_function(int n) {
    int result = 0;
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            for (int k = 0; k < n; k++) {
                result += i * j * k;
            }
        }
    }
    return result;
}
'''
        
        test_file = self._create_test_file("high_complexity.c", high_complexity_code)
        result = self.analyzer.analyze([test_file], {})
        
        self.assertEqual(result.analyzer, "performance_analyzer")
        self.assertIn(result.status, [AnalysisStatus.WARNING, AnalysisStatus.FAILURE])
        
        # Should find high complexity issues
        complexity_findings = [f for f in result.findings if 'complexity' in f.type]
        self.assertGreater(len(complexity_findings), 0)
    
    def test_memory_allocation_analysis(self):
        """Test memory allocation pattern analysis."""
        # Code with memory allocation issues
        memory_code = '''
static int memory_function(void) {
    char *buffer = kmalloc(1024 * 1024, GFP_KERNEL);  // Large allocation
    char *small = kmalloc(16, GFP_KERNEL);  // Small allocation
    char *unsafe = kmalloc(size * count, GFP_KERNEL);  // Unsafe multiplication
    
    // Missing kfree for buffer and small
    return 0;
}
'''
        
        test_file = self._create_test_file("memory_issues.c", memory_code)
        result = self.analyzer.analyze([test_file], {})
        
        self.assertEqual(result.analyzer, "performance_analyzer")
        
        # Should find memory-related issues
        memory_findings = [f for f in result.findings if 'memory' in f.type or 'allocation' in f.type]
        self.assertGreater(len(memory_findings), 0)
    
    def test_io_efficiency_analysis(self):
        """Test I/O efficiency analysis."""
        # Code with I/O efficiency issues
        io_code = '''
static void io_function(void __iomem *base) {
    // Inefficient polling loop
    while (readl(base + STATUS_REG) & BUSY_FLAG) {
        // Busy waiting
    }
    
    // Excessive delay
    udelay(5000);  // 5ms delay using udelay
    mdelay(100);   // 100ms busy wait
    
    // Byte-by-byte I/O
    for (int i = 0; i < 1024; i++) {
        outb(data[i], port + i);
    }
    
    // Write without barrier
    writel(value, base + CONTROL_REG);
}
'''
        
        test_file = self._create_test_file("io_issues.c", io_code)
        result = self.analyzer.analyze([test_file], {})
        
        self.assertEqual(result.analyzer, "performance_analyzer")
        
        # Should find I/O-related issues
        io_findings = [f for f in result.findings if 'io' in f.type or 'delay' in f.type or 'polling' in f.type]
        self.assertGreater(len(io_findings), 0)
    
    def test_dma_analysis(self):
        """Test DMA usage analysis."""
        # Code with DMA issues
        dma_code = '''
static int dma_function(struct device *dev) {
    dma_addr_t dma_handle;
    void *coherent_mem;
    
    // DMA allocation without proper cleanup
    coherent_mem = dma_alloc_coherent(dev, 4096, &dma_handle, GFP_KERNEL);
    
    // DMA mapping without error checking
    dma_addr_t mapped = dma_map_single(dev, buffer, size, DMA_TO_DEVICE);
    
    // Large copy that could use DMA
    memcpy(dest, src, 65536);
    
    return 0;  // Missing dma_free_coherent and dma_unmap_single
}
'''
        
        test_file = self._create_test_file("dma_issues.c", dma_code)
        result = self.analyzer.analyze([test_file], {})
        
        self.assertEqual(result.analyzer, "performance_analyzer")
        
        # Should find DMA-related issues
        dma_findings = [f for f in result.findings if 'dma' in f.type]
        self.assertGreater(len(dma_findings), 0)
    
    def test_performance_anti_patterns(self):
        """Test detection of performance anti-patterns."""
        # Code with anti-patterns
        anti_pattern_code = '''
static void anti_pattern_function(void) {
    for (int i = 0; i < 1000; i++) {
        // String operation in loop
        int len = strlen(some_string);
        
        // Memory allocation in loop
        char *temp = kmalloc(64, GFP_KERNEL);
        
        // Use temp...
        kfree(temp);
    }
}
'''
        
        test_file = self._create_test_file("anti_patterns.c", anti_pattern_code)
        result = self.analyzer.analyze([test_file], {})
        
        self.assertEqual(result.analyzer, "performance_analyzer")
        
        # Should find anti-pattern issues
        anti_pattern_findings = [f for f in result.findings if 'loop' in f.type]
        self.assertGreater(len(anti_pattern_findings), 0)
    
    def test_clean_code_analysis(self):
        """Test analysis of clean, efficient code."""
        # Well-written code with good performance patterns
        clean_code = '''
static int efficient_function(struct device *dev, void *data, size_t size) {
    dma_addr_t dma_handle;
    void *coherent_mem;
    int ret = 0;
    
    // Efficient DMA allocation
    coherent_mem = dma_alloc_coherent(dev, size, &dma_handle, GFP_KERNEL);
    if (!coherent_mem)
        return -ENOMEM;
    
    // Efficient bulk I/O
    iowrite32_rep(base_addr, data, size / 4);
    
    // Proper memory barrier
    wmb();
    
    // Proper cleanup
    dma_free_coherent(dev, size, coherent_mem, dma_handle);
    
    return ret;
}
'''
        
        test_file = self._create_test_file("clean_code.c", clean_code)
        result = self.analyzer.analyze([test_file], {})
        
        self.assertEqual(result.analyzer, "performance_analyzer")
        self.assertEqual(result.status, AnalysisStatus.SUCCESS)
        
        # Should have fewer or no critical issues
        critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
        self.assertEqual(len(critical_findings), 0)
    
    def test_empty_file_analysis(self):
        """Test analysis of empty or invalid files."""
        # Empty file
        test_file = self._create_test_file("empty.c", "")
        result = self.analyzer.analyze([test_file], {})
        
        self.assertEqual(result.analyzer, "performance_analyzer")
        self.assertEqual(result.status, AnalysisStatus.SUCCESS)
    
    def test_nonexistent_file_analysis(self):
        """Test analysis with nonexistent files."""
        result = self.analyzer.analyze(["nonexistent.c"], {})
        
        self.assertEqual(result.analyzer, "performance_analyzer")
        self.assertEqual(result.status, AnalysisStatus.FAILURE)
        self.assertGreater(len(result.findings), 0)
    
    def test_custom_configuration(self):
        """Test analyzer with custom configuration."""
        config = PerformanceConfiguration(
            check_types=[PerformanceCheckType.ALGORITHMIC_COMPLEXITY],
            max_complexity_threshold=5,  # Lower threshold
            timeout=60
        )
        
        analyzer = PerformanceAnalyzer(config)
        
        # Simple function that would pass default threshold but fail lower one
        simple_code = '''
static int simple_function(int n) {
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            // Simple nested loop
            result += i + j;
        }
    }
    return result;
}
'''
        
        test_file = self._create_test_file("simple.c", simple_code)
        result = analyzer.analyze([test_file], {})
        
        self.assertEqual(result.analyzer, "performance_analyzer")
        # Should find issues due to lower threshold
        complexity_findings = [f for f in result.findings if 'complexity' in f.type]
        self.assertGreater(len(complexity_findings), 0)


if __name__ == '__main__':
    unittest.main()