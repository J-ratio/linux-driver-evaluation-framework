#!/usr/bin/env python3
"""
Advanced Features Analyzer Demo

This script demonstrates the advanced features analyzer by analyzing
sample driver code with various sophisticated features.
"""

import os
import sys
import tempfile
from pathlib import Path

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.analyzers.advanced_features_analyzer import AdvancedFeaturesAnalyzer, AdvancedFeaturesConfiguration


def create_sample_advanced_driver():
    """Create a sample driver with advanced features."""
    return '''
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/pm_runtime.h>
#include <linux/interrupt.h>
#include <linux/clk.h>
#include <linux/regulator/consumer.h>
#include <linux/gpio/consumer.h>

struct advanced_driver_data {
    struct device *dev;
    void __iomem *base;
    struct clk *clk;
    struct regulator *vdd;
    struct gpio_desc *reset_gpio;
    int irq;
};

static const struct of_device_id advanced_driver_of_match[] = {
    { .compatible = "vendor,advanced-device-v1" },
    { .compatible = "vendor,advanced-device-v2" },
    { }
};
MODULE_DEVICE_TABLE(of, advanced_driver_of_match);

static irqreturn_t advanced_driver_irq_handler(int irq, void *dev_id)
{
    struct advanced_driver_data *drvdata = dev_id;
    
    /* Quick hardware status check */
    if (readl(drvdata->base + 0x10) & BIT(0))
        return IRQ_WAKE_THREAD;
    
    return IRQ_NONE;
}

static irqreturn_t advanced_driver_threaded_irq(int irq, void *dev_id)
{
    struct advanced_driver_data *drvdata = dev_id;
    
    /* Heavy processing in thread context */
    dev_dbg(drvdata->dev, "Processing interrupt in thread context\\n");
    
    /* Clear interrupt */
    writel(BIT(0), drvdata->base + 0x14);
    
    return IRQ_HANDLED;
}

static int advanced_driver_runtime_suspend(struct device *dev)
{
    struct advanced_driver_data *drvdata = dev_get_drvdata(dev);
    
    dev_dbg(dev, "Runtime suspend\\n");
    
    /* Disable clock to save power */
    clk_disable_unprepare(drvdata->clk);
    
    /* Disable regulator if possible */
    regulator_disable(drvdata->vdd);
    
    return 0;
}

static int advanced_driver_runtime_resume(struct device *dev)
{
    struct advanced_driver_data *drvdata = dev_get_drvdata(dev);
    int ret;
    
    dev_dbg(dev, "Runtime resume\\n");
    
    /* Enable regulator */
    ret = regulator_enable(drvdata->vdd);
    if (ret) {
        dev_err(dev, "Failed to enable regulator: %d\\n", ret);
        return ret;
    }
    
    /* Enable clock */
    ret = clk_prepare_enable(drvdata->clk);
    if (ret) {
        dev_err(dev, "Failed to enable clock: %d\\n", ret);
        regulator_disable(drvdata->vdd);
        return ret;
    }
    
    return 0;
}

static int advanced_driver_suspend(struct device *dev)
{
    struct advanced_driver_data *drvdata = dev_get_drvdata(dev);
    
    dev_dbg(dev, "System suspend\\n");
    
    /* Configure as wake source if needed */
    if (device_may_wakeup(dev))
        enable_irq_wake(drvdata->irq);
    
    return pm_runtime_force_suspend(dev);
}

static int advanced_driver_resume(struct device *dev)
{
    struct advanced_driver_data *drvdata = dev_get_drvdata(dev);
    int ret;
    
    dev_dbg(dev, "System resume\\n");
    
    ret = pm_runtime_force_resume(dev);
    if (ret)
        return ret;
    
    if (device_may_wakeup(dev))
        disable_irq_wake(drvdata->irq);
    
    return 0;
}

static const struct dev_pm_ops advanced_driver_pm_ops = {
    SET_SYSTEM_SLEEP_PM_OPS(advanced_driver_suspend, advanced_driver_resume)
    SET_RUNTIME_PM_OPS(advanced_driver_runtime_suspend, 
                       advanced_driver_runtime_resume, NULL)
};

static int advanced_driver_parse_dt(struct platform_device *pdev,
                                   struct advanced_driver_data *drvdata)
{
    struct device *dev = &pdev->dev;
    struct device_node *np = dev->of_node;
    u32 clock_frequency;
    const char *mode_string;
    
    /* Parse clock frequency */
    if (of_property_read_u32(np, "clock-frequency", &clock_frequency)) {
        dev_err(dev, "Missing clock-frequency property\\n");
        return -EINVAL;
    }
    
    /* Parse operating mode */
    if (of_property_read_string(np, "operating-mode", &mode_string)) {
        dev_warn(dev, "No operating mode specified, using default\\n");
        mode_string = "normal";
    }
    
    /* Parse GPIO for reset */
    drvdata->reset_gpio = devm_gpiod_get_optional(dev, "reset", GPIOD_OUT_HIGH);
    if (IS_ERR(drvdata->reset_gpio)) {
        dev_err(dev, "Failed to get reset GPIO\\n");
        return PTR_ERR(drvdata->reset_gpio);
    }
    
    dev_info(dev, "Parsed DT: freq=%u, mode=%s\\n", clock_frequency, mode_string);
    
    return 0;
}

static int advanced_driver_probe(struct platform_device *pdev)
{
    struct device *dev = &pdev->dev;
    struct advanced_driver_data *drvdata;
    struct resource *res;
    int ret;
    
    drvdata = devm_kzalloc(dev, sizeof(*drvdata), GFP_KERNEL);
    if (!drvdata)
        return -ENOMEM;
    
    drvdata->dev = dev;
    platform_set_drvdata(pdev, drvdata);
    
    /* Parse device tree properties */
    ret = advanced_driver_parse_dt(pdev, drvdata);
    if (ret)
        return ret;
    
    /* Get memory resource */
    res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
    drvdata->base = devm_ioremap_resource(dev, res);
    if (IS_ERR(drvdata->base))
        return PTR_ERR(drvdata->base);
    
    /* Get clock */
    drvdata->clk = devm_clk_get(dev, "main");
    if (IS_ERR(drvdata->clk)) {
        dev_err(dev, "Failed to get main clock\\n");
        return PTR_ERR(drvdata->clk);
    }
    
    /* Get regulator */
    drvdata->vdd = devm_regulator_get(dev, "vdd");
    if (IS_ERR(drvdata->vdd)) {
        dev_err(dev, "Failed to get VDD regulator\\n");
        return PTR_ERR(drvdata->vdd);
    }
    
    /* Set regulator voltage if specified in DT */
    ret = regulator_set_voltage(drvdata->vdd, 3300000, 3300000);
    if (ret) {
        dev_warn(dev, "Failed to set regulator voltage: %d\\n", ret);
    }
    
    /* Get interrupt */
    drvdata->irq = platform_get_irq(pdev, 0);
    if (drvdata->irq < 0)
        return drvdata->irq;
    
    /* Request threaded IRQ with advanced flags */
    ret = devm_request_threaded_irq(dev, drvdata->irq,
                                   advanced_driver_irq_handler,
                                   advanced_driver_threaded_irq,
                                   IRQF_SHARED | IRQF_ONESHOT | IRQF_TRIGGER_RISING,
                                   dev_name(dev), drvdata);
    if (ret) {
        dev_err(dev, "Failed to request IRQ %d: %d\\n", drvdata->irq, ret);
        return ret;
    }
    
    /* Enable runtime PM */
    pm_runtime_set_active(dev);
    pm_runtime_enable(dev);
    pm_runtime_get_sync(dev);
    
    /* Initialize hardware */
    ret = clk_prepare_enable(drvdata->clk);
    if (ret) {
        dev_err(dev, "Failed to enable clock: %d\\n", ret);
        goto err_pm;
    }
    
    ret = regulator_enable(drvdata->vdd);
    if (ret) {
        dev_err(dev, "Failed to enable regulator: %d\\n", ret);
        goto err_clk;
    }
    
    /* Reset device if GPIO available */
    if (drvdata->reset_gpio) {
        gpiod_set_value_cansleep(drvdata->reset_gpio, 0);
        usleep_range(1000, 2000);
        gpiod_set_value_cansleep(drvdata->reset_gpio, 1);
        usleep_range(1000, 2000);
    }
    
    /* Configure device as potential wake source */
    device_init_wakeup(dev, true);
    
    dev_info(dev, "Advanced driver probed successfully\\n");
    
    pm_runtime_put(dev);
    return 0;
    
err_clk:
    clk_disable_unprepare(drvdata->clk);
err_pm:
    pm_runtime_put(dev);
    pm_runtime_disable(dev);
    return ret;
}

static int advanced_driver_remove(struct platform_device *pdev)
{
    struct device *dev = &pdev->dev;
    struct advanced_driver_data *drvdata = platform_get_drvdata(pdev);
    
    device_init_wakeup(dev, false);
    
    pm_runtime_get_sync(dev);
    
    regulator_disable(drvdata->vdd);
    clk_disable_unprepare(drvdata->clk);
    
    pm_runtime_put(dev);
    pm_runtime_disable(dev);
    
    dev_info(dev, "Advanced driver removed\\n");
    
    return 0;
}

static struct platform_driver advanced_driver = {
    .probe = advanced_driver_probe,
    .remove = advanced_driver_remove,
    .driver = {
        .name = "advanced-driver",
        .of_match_table = advanced_driver_of_match,
        .pm = &advanced_driver_pm_ops,
    },
};

module_platform_driver(advanced_driver);

MODULE_AUTHOR("Linux Driver Evaluation Framework");
MODULE_DESCRIPTION("Advanced Linux Driver with Power Management, DT, and IRQ features");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:advanced-driver");
'''


def create_basic_driver():
    """Create a basic driver without advanced features."""
    return '''
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/io.h>

struct basic_driver_data {
    void __iomem *base;
};

static int basic_driver_probe(struct platform_device *pdev)
{
    struct device *dev = &pdev->dev;
    struct basic_driver_data *drvdata;
    struct resource *res;
    
    drvdata = devm_kzalloc(dev, sizeof(*drvdata), GFP_KERNEL);
    if (!drvdata)
        return -ENOMEM;
    
    res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
    drvdata->base = devm_ioremap_resource(dev, res);
    if (IS_ERR(drvdata->base))
        return PTR_ERR(drvdata->base);
    
    platform_set_drvdata(pdev, drvdata);
    
    dev_info(dev, "Basic driver probed\\n");
    
    return 0;
}

static int basic_driver_remove(struct platform_device *pdev)
{
    dev_info(&pdev->dev, "Basic driver removed\\n");
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

MODULE_AUTHOR("Linux Driver Evaluation Framework");
MODULE_DESCRIPTION("Basic Linux Driver without advanced features");
MODULE_LICENSE("GPL v2");
'''


def analyze_driver(analyzer, driver_code, driver_name):
    """Analyze a driver and print results."""
    print(f"\\n{'='*60}")
    print(f"Analyzing {driver_name}")
    print(f"{'='*60}")
    
    # Create temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
        f.write(driver_code)
        temp_file = f.name
    
    try:
        # Run analysis
        result = analyzer.analyze([temp_file], {})
        
        print(f"Status: {result.status.value}")
        print(f"Score: {result.score:.1f}/100.0")
        print(f"Total findings: {len(result.findings)}")
        
        # Print detected features
        detected_features = result.metrics.get("detected_features", {})
        feature_scores = result.metrics.get("feature_scores", {})
        
        print("\\nDetected Advanced Features:")
        for feature_type, metrics in detected_features.items():
            score = feature_scores.get(feature_type, 0.0)
            print(f"  {feature_type.replace('_', ' ').title()}: {score:.1%}")
            
            # Show specific detected patterns
            patterns = metrics.get("detected_patterns", [])
            if patterns:
                print(f"    Detected patterns: {len(patterns)}")
                for pattern in patterns[:3]:  # Show first 3 patterns
                    print(f"      Line {pattern['line']}: {pattern['pattern']}")
                if len(patterns) > 3:
                    print(f"      ... and {len(patterns) - 3} more")
        
        # Print findings summary
        if result.findings:
            print("\\nFindings Summary:")
            finding_types = {}
            for finding in result.findings:
                finding_types[finding.type] = finding_types.get(finding.type, 0) + 1
            
            for finding_type, count in finding_types.items():
                print(f"  {finding_type}: {count}")
        
        # Print some example findings
        if result.findings:
            print("\\nExample Findings:")
            for finding in result.findings[:5]:  # Show first 5 findings
                print(f"  [{finding.severity.value.upper()}] {finding.type}")
                print(f"    File: {finding.file}, Line: {finding.line}")
                print(f"    Message: {finding.message}")
                print(f"    Recommendation: {finding.recommendation}")
                print()
    
    finally:
        # Clean up temporary file
        os.unlink(temp_file)


def main():
    """Main demo function."""
    print("Advanced Features Analyzer Demo")
    print("===============================")
    
    # Create analyzer with default configuration
    analyzer = AdvancedFeaturesAnalyzer()
    
    print(f"Analyzer: {analyzer.name} v{analyzer.version}")
    print(f"Feature types: {[ft.value for ft in analyzer.config.feature_types]}")
    print(f"Weights: PM={analyzer.config.power_mgmt_weight}, "
          f"DT={analyzer.config.device_tree_weight}, "
          f"IRQ={analyzer.config.interrupt_weight}")
    
    # Analyze advanced driver
    advanced_code = create_sample_advanced_driver()
    analyze_driver(analyzer, advanced_code, "Advanced Driver")
    
    # Analyze basic driver for comparison
    basic_code = create_basic_driver()
    analyze_driver(analyzer, basic_code, "Basic Driver")
    
    print(f"\\n{'='*60}")
    print("Demo completed!")
    print("The advanced driver shows sophisticated features like:")
    print("- Runtime and system power management")
    print("- Device tree property parsing and GPIO handling")
    print("- Threaded interrupt handling with advanced flags")
    print("- Clock and regulator management")
    print("\\nThe basic driver shows minimal features and gets a low score.")


if __name__ == "__main__":
    main()