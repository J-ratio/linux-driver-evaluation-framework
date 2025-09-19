#!/usr/bin/env python3
"""
Code Quality Analyzer Demo

This script demonstrates the code quality analyzer functionality
by analyzing sample driver code for style, complexity, and documentation issues.
"""

import os
import sys
import tempfile
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.analyzers.code_quality_analyzer import CodeQualityAnalyzer, CodeQualityConfiguration, CodeQualityCheckType


def create_sample_driver_code():
    """Create sample driver code with various quality issues."""
    
    # Sample driver with quality issues
    sample_code = '''
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>

// This is a very long line that exceeds the 80 character limit and should be flagged by checkpatch as a style violation
static int device_data = 0;   

struct device_info {
    int id;
    char name[64];
    void *private_data;
};

static int complex_function(int a, int b, int c, int d) {
    if (a > 0) {
        if (b > 0) {
            if (c > 0) {
                if (d > 0) {
                    if (a > b) {
                        if (b > c) {
                            if (c > d) {
                                return a + b + c + d;
                            } else if (d > c) {
                                return a * b * c * d;
                            } else {
                                return a - b - c - d;
                            }
                        } else {
                            return a + b - c - d;
                        }
                    } else {
                        return b + c + d - a;
                    }
                } else {
                    return a + b + c;
                }
            } else {
                return a + b;
            }
        } else {
            return a;
        }
    } else {
        return 0;
    }
}

/**
 * documented_function - This function has proper documentation
 * @param: Input parameter
 *
 * Return: 0 on success, negative on error
 */
static int documented_function(int param) {
    return param > 0 ? param : -EINVAL;
}

static int undocumented_function(struct platform_device *pdev) {
    struct device_info *info;
    
    info = kmalloc(sizeof(*info), GFP_KERNEL);
    if (!info)
        return -ENOMEM;
    
    strcpy(info->name, "test_device");  // Dangerous function usage
    
    platform_set_drvdata(pdev, info);
    return 0;
}

static int driver_remove(struct platform_device *pdev) {
    struct device_info *info = platform_get_drvdata(pdev);
    
    kfree(info);
    return 0;
}

static struct platform_driver sample_driver = {
    .probe = undocumented_function,
    .remove = driver_remove,
    .driver = {
        .name = "sample_driver",
    },
};

static int __init sample_init(void) {
    return platform_driver_register(&sample_driver);
}

static void __exit sample_exit(void) {
    platform_driver_unregister(&sample_driver);
}

module_init(sample_init);
module_exit(sample_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Sample driver for code quality analysis");
MODULE_AUTHOR("Test Author");
'''
    
    return sample_code


def run_code_quality_demo():
    """Run the code quality analyzer demo."""
    print("=" * 60)
    print("Code Quality Analyzer Demo")
    print("=" * 60)
    
    # Create temporary file with sample code
    with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
        sample_code = create_sample_driver_code()
        f.write(sample_code)
        temp_file = f.name
    
    try:
        # Create analyzer with different configurations
        configs = [
            {
                'name': 'Basic Analysis',
                'config': CodeQualityConfiguration(
                    check_types=[CodeQualityCheckType.CHECKPATCH, CodeQualityCheckType.COMPLEXITY, CodeQualityCheckType.DOCUMENTATION],
                    max_complexity=10,
                    min_doc_coverage=0.5
                )
            },
            {
                'name': 'Strict Analysis',
                'config': CodeQualityConfiguration(
                    check_types=[CodeQualityCheckType.ALL],
                    checkpatch_strict=True,
                    max_complexity=5,
                    min_doc_coverage=0.8
                )
            }
        ]
        
        for config_info in configs:
            print(f"\n{config_info['name']}:")
            print("-" * 40)
            
            analyzer = CodeQualityAnalyzer(config_info['config'])
            result = analyzer.analyze([temp_file], {})
            
            print(f"Status: {result.status.value}")
            print(f"Score: {result.score:.1f}/100")
            print(f"Total Findings: {len(result.findings)}")
            
            # Group findings by type
            findings_by_type = {}
            for finding in result.findings:
                finding_type = finding.type
                if finding_type not in findings_by_type:
                    findings_by_type[finding_type] = []
                findings_by_type[finding_type].append(finding)
            
            print("\nFindings by Type:")
            for finding_type, findings in findings_by_type.items():
                print(f"  {finding_type}: {len(findings)} issues")
                
                # Show first few findings of each type
                for i, finding in enumerate(findings[:3]):
                    severity_icon = {
                        'critical': '🔴',
                        'high': '🟠', 
                        'medium': '🟡',
                        'low': '🔵',
                        'info': '⚪'
                    }.get(finding.severity.value, '❓')
                    
                    print(f"    {severity_icon} Line {finding.line}: {finding.message}")
                
                if len(findings) > 3:
                    print(f"    ... and {len(findings) - 3} more")
            
            # Show metrics
            print(f"\nMetrics:")
            print(f"  Files analyzed: {result.metrics.get('files_analyzed', 0)}")
            print(f"  Checkpatch violations: {result.metrics.get('checkpatch_violations', 0)}")
            print(f"  Complexity violations: {result.metrics.get('complexity_violations', 0)}")
            print(f"  Documentation issues: {result.metrics.get('documentation_issues', 0)}")
            
            # Show severity distribution
            severity_dist = result.metrics.get('severity_distribution', {})
            if severity_dist:
                print(f"  Severity distribution:")
                for severity, count in severity_dist.items():
                    if count > 0:
                        print(f"    {severity}: {count}")
    
    finally:
        # Clean up temporary file
        os.unlink(temp_file)
    
    print("\n" + "=" * 60)
    print("Demo completed!")
    print("\nThe code quality analyzer detected:")
    print("• Style violations (long lines, dangerous functions)")
    print("• High complexity functions that need refactoring")
    print("• Missing documentation for functions and structures")
    print("• Various maintainability issues")
    print("\nThis helps ensure Linux driver code meets quality standards!")


if __name__ == '__main__':
    run_code_quality_demo()