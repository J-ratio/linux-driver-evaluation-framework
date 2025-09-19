"""
Tests for the Advanced Features Analyzer.

This module contains unit tests for the advanced features analyzer,
testing power management, device tree, and interrupt handling detection.
"""

import unittest
import tempfile
import os
from unittest.mock import patch, MagicMock

from src.analyzers.advanced_features_analyzer import (
    AdvancedFeaturesAnalyzer, 
    AdvancedFeaturesConfiguration,
    AdvancedFeatureType
)
from src.core.interfaces import AnalysisStatus, Severity


class TestAdvancedFeaturesAnalyzer(unittest.TestCase):
    """Test cases for the Advanced Features Analyzer."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = AdvancedFeaturesAnalyzer()
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_analyzer_properties(self):
        """Test analyzer basic properties."""
        self.assertEqual(self.analyzer.name, "advanced_features_analyzer")
        self.assertEqual(self.analyzer.version, "1.0.0")
    
    def test_validate_config_valid(self):
        """Test configuration validation with valid config."""
        valid_config = {
            'timeout': 300,
            'power_mgmt_weight': 0.4,
            'device_tree_weight': 0.3,
            'interrupt_weight': 0.3
        }
        self.assertTrue(self.analyzer.validate_config(valid_config))
    
    def test_validate_config_invalid(self):
        """Test configuration validation with invalid config."""
        invalid_configs = [
            {'timeout': 'invalid'},
            {'power_mgmt_weight': -0.1},
            {'device_tree_weight': 1.5},
            {'interrupt_weight': 'invalid'}
        ]
        
        for config in invalid_configs:
            with self.subTest(config=config):
                self.assertFalse(self.analyzer.validate_config(config))
    
    def test_analyze_no_files(self):
        """Test analysis with no source files."""
        result = self.analyzer.analyze([], {})
        
        self.assertEqual(result.analyzer, "advanced_features_analyzer")
        self.assertEqual(result.status, AnalysisStatus.FAILURE)
        self.assertEqual(result.score, 0.0)
        self.assertFalse(result.metrics.get("advanced_features_attempted", True))
    
    def test_power_management_detection(self):
        """Test power management feature detection."""
        # Create test file with power management code
        test_code = '''
#include <linux/pm.h>
#include <linux/pm_runtime.h>

static int my_driver_suspend(struct device *dev)
{
    pm_runtime_put(dev);
    return 0;
}

static int my_driver_resume(struct device *dev)
{
    pm_runtime_get(dev);
    return 0;
}

static const struct dev_pm_ops my_driver_pm_ops = {
    SET_SYSTEM_SLEEP_PM_OPS(my_driver_suspend, my_driver_resume)
    SET_RUNTIME_PM_OPS(my_driver_suspend, my_driver_resume, NULL)
};
'''
        
        test_file = os.path.join(self.temp_dir, "test_driver.c")
        with open(test_file, 'w') as f:
            f.write(test_code)
        
        result = self.analyzer.analyze([test_file], {})
        
        self.assertEqual(result.status, AnalysisStatus.SUCCESS)
        self.assertTrue(result.metrics.get("advanced_features_attempted", False))
        
        # Check for power management findings
        power_findings = [f for f in result.findings if "power_mgmt" in f.type]
        self.assertGreater(len(power_findings), 0)
        
        # Check metrics
        detected_features = result.metrics.get("detected_features", {})
        self.assertIn("power_management", detected_features)
    
    def test_device_tree_detection(self):
        """Test device tree integration detection."""
        test_code = '''
#include <linux/of.h>
#include <linux/of_device.h>

static const struct of_device_id my_driver_of_match[] = {
    { .compatible = "vendor,my-device" },
    { }
};
MODULE_DEVICE_TABLE(of, my_driver_of_match);

static int my_driver_probe(struct platform_device *pdev)
{
    struct device_node *np = pdev->dev.of_node;
    u32 value;
    
    if (of_property_read_u32(np, "clock-frequency", &value)) {
        dev_err(&pdev->dev, "Failed to read clock-frequency\\n");
        return -EINVAL;
    }
    
    return 0;
}
'''
        
        test_file = os.path.join(self.temp_dir, "test_driver.c")
        with open(test_file, 'w') as f:
            f.write(test_code)
        
        result = self.analyzer.analyze([test_file], {})
        
        self.assertEqual(result.status, AnalysisStatus.SUCCESS)
        
        # Check for device tree findings
        dt_findings = [f for f in result.findings if "device_tree" in f.type]
        self.assertGreater(len(dt_findings), 0)
        
        # Check metrics
        detected_features = result.metrics.get("detected_features", {})
        self.assertIn("device_tree", detected_features)
    
    def test_interrupt_handling_detection(self):
        """Test interrupt handling sophistication detection."""
        test_code = '''
#include <linux/interrupt.h>
#include <linux/workqueue.h>

static irqreturn_t my_driver_irq_handler(int irq, void *dev_id)
{
    // Quick processing
    return IRQ_WAKE_THREAD;
}

static irqreturn_t my_driver_threaded_irq(int irq, void *dev_id)
{
    // Heavy processing in thread context
    return IRQ_HANDLED;
}

static int my_driver_probe(struct platform_device *pdev)
{
    int irq = platform_get_irq(pdev, 0);
    
    return devm_request_threaded_irq(&pdev->dev, irq,
                                   my_driver_irq_handler,
                                   my_driver_threaded_irq,
                                   IRQF_SHARED | IRQF_ONESHOT,
                                   "my-driver", pdev);
}
'''
        
        test_file = os.path.join(self.temp_dir, "test_driver.c")
        with open(test_file, 'w') as f:
            f.write(test_code)
        
        result = self.analyzer.analyze([test_file], {})
        
        self.assertEqual(result.status, AnalysisStatus.SUCCESS)
        
        # Check for interrupt handling findings
        irq_findings = [f for f in result.findings if "interrupt" in f.type]
        self.assertGreater(len(irq_findings), 0)
        
        # Check metrics
        detected_features = result.metrics.get("detected_features", {})
        self.assertIn("interrupt_handling", detected_features)
    
    def test_comprehensive_advanced_driver(self):
        """Test detection of multiple advanced features in one driver."""
        test_code = '''
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/pm_runtime.h>
#include <linux/interrupt.h>
#include <linux/clk.h>

static const struct of_device_id advanced_driver_of_match[] = {
    { .compatible = "vendor,advanced-device" },
    { }
};
MODULE_DEVICE_TABLE(of, advanced_driver_of_match);

static irqreturn_t advanced_driver_irq(int irq, void *dev_id)
{
    return IRQ_WAKE_THREAD;
}

static irqreturn_t advanced_driver_threaded_irq(int irq, void *dev_id)
{
    return IRQ_HANDLED;
}

static int advanced_driver_suspend(struct device *dev)
{
    pm_runtime_put(dev);
    return 0;
}

static int advanced_driver_resume(struct device *dev)
{
    pm_runtime_get(dev);
    return 0;
}

static const struct dev_pm_ops advanced_driver_pm_ops = {
    SET_SYSTEM_SLEEP_PM_OPS(advanced_driver_suspend, advanced_driver_resume)
    SET_RUNTIME_PM_OPS(advanced_driver_suspend, advanced_driver_resume, NULL)
};

static int advanced_driver_probe(struct platform_device *pdev)
{
    struct device *dev = &pdev->dev;
    struct clk *clk;
    u32 frequency;
    int irq;
    
    // Device tree property parsing
    if (of_property_read_u32(dev->of_node, "clock-frequency", &frequency)) {
        dev_err(dev, "Failed to read clock-frequency\\n");
        return -EINVAL;
    }
    
    // Clock management
    clk = devm_clk_get(dev, "main");
    if (IS_ERR(clk))
        return PTR_ERR(clk);
    
    clk_prepare_enable(clk);
    
    // Interrupt handling
    irq = platform_get_irq(pdev, 0);
    if (irq < 0)
        return irq;
    
    devm_request_threaded_irq(dev, irq, advanced_driver_irq,
                             advanced_driver_threaded_irq,
                             IRQF_SHARED | IRQF_ONESHOT,
                             "advanced-driver", pdev);
    
    // Runtime PM
    pm_runtime_enable(dev);
    pm_runtime_get_sync(dev);
    
    return 0;
}

static struct platform_driver advanced_driver = {
    .probe = advanced_driver_probe,
    .driver = {
        .name = "advanced-driver",
        .of_match_table = advanced_driver_of_match,
        .pm = &advanced_driver_pm_ops,
    },
};
module_platform_driver(advanced_driver);
'''
        
        test_file = os.path.join(self.temp_dir, "advanced_driver.c")
        with open(test_file, 'w') as f:
            f.write(test_code)
        
        result = self.analyzer.analyze([test_file], {})
        
        self.assertEqual(result.status, AnalysisStatus.SUCCESS)
        self.assertGreater(result.score, 0.0)
        
        # Should detect all three feature types
        detected_features = result.metrics.get("detected_features", {})
        self.assertIn("power_management", detected_features)
        self.assertIn("device_tree", detected_features)
        self.assertIn("interrupt_handling", detected_features)
        
        # Should have findings for each feature type
        finding_types = {f.type for f in result.findings}
        self.assertTrue(any("power_mgmt" in t for t in finding_types))
        self.assertTrue(any("device_tree" in t for t in finding_types))
        self.assertTrue(any("interrupt" in t for t in finding_types))
    
    def test_basic_driver_low_score(self):
        """Test that basic drivers without advanced features get low scores."""
        basic_code = '''
#include <linux/module.h>
#include <linux/platform_device.h>

static int basic_driver_probe(struct platform_device *pdev)
{
    printk(KERN_INFO "Basic driver probed\\n");
    return 0;
}

static int basic_driver_remove(struct platform_device *pdev)
{
    printk(KERN_INFO "Basic driver removed\\n");
    return 0;
}

static struct platform_driver basic_driver = {
    .probe = basic_driver_probe,
    .remove = basic_driver_remove,
    .driver = {
        .name = "basic-driver",
    },
};
module_platform_driver(basic_driver);
'''
        
        test_file = os.path.join(self.temp_dir, "basic_driver.c")
        with open(test_file, 'w') as f:
            f.write(basic_code)
        
        result = self.analyzer.analyze([test_file], {})
        
        self.assertEqual(result.status, AnalysisStatus.SUCCESS)
        self.assertEqual(result.score, 0.0)  # No advanced features detected


if __name__ == '__main__':
    unittest.main()