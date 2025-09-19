"""
Advanced features analyzer for Linux kernel driver code.

This module provides comprehensive analysis of sophisticated driver features by implementing:
- Pattern matching for power management features
- Device tree integration detection algorithms  
- Interrupt handling sophistication analysis
"""

import os
import re
import tempfile
import shutil
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from src.core.interfaces import BaseAnalyzer, AnalysisResult, AnalysisStatus, Finding, Severity


class AdvancedFeatureType(Enum):
    """Types of advanced feature checks."""
    POWER_MANAGEMENT = "power_management"
    DEVICE_TREE = "device_tree"
    INTERRUPT_HANDLING = "interrupt_handling"
    ALL = "all"


@dataclass
class AdvancedFeaturesConfiguration:
    """Configuration for advanced features analysis."""
    feature_types: List[AdvancedFeatureType]
    timeout: int = 300
    power_mgmt_weight: float = 0.4
    device_tree_weight: float = 0.3
    interrupt_weight: float = 0.3
    enable_detailed_analysis: bool = True
    
    def __post_init__(self):
        if not self.feature_types:
            self.feature_types = [
                AdvancedFeatureType.POWER_MANAGEMENT,
                AdvancedFeatureType.DEVICE_TREE,
                AdvancedFeatureType.INTERRUPT_HANDLING
            ]


class AdvancedFeaturesAnalyzer(BaseAnalyzer):
    """
    Advanced features analyzer for Linux kernel driver code.
    
    This analyzer detects and evaluates sophisticated driver implementations including:
    - Power management features (suspend/resume, runtime PM, etc.)
    - Device tree integration (DT bindings, property parsing, etc.)
    - Interrupt handling sophistication (threaded IRQs, shared IRQs, etc.)
    """
    
    # Power management patterns
    POWER_MGMT_PATTERNS = {
        'suspend_resume': [
            r'\.suspend\s*=\s*\w+',
            r'\.resume\s*=\s*\w+',
            r'suspend_late',
            r'resume_early',
            r'freeze',
            r'thaw',
            r'poweroff',
            r'restore'
        ],
        'runtime_pm': [
            r'pm_runtime_enable',
            r'pm_runtime_disable',
            r'pm_runtime_get',
            r'pm_runtime_put',
            r'pm_runtime_suspend',
            r'pm_runtime_resume',
            r'pm_runtime_idle',
            r'pm_runtime_set_active',
            r'pm_runtime_set_suspended'
        ],
        'power_states': [
            r'SET_SYSTEM_SLEEP_PM_OPS',
            r'SET_RUNTIME_PM_OPS',
            r'SIMPLE_DEV_PM_OPS',
            r'UNIVERSAL_DEV_PM_OPS',
            r'pm_sleep_ptr',
            r'DEFINE_SIMPLE_DEV_PM_OPS'
        ],
        'clock_management': [
            r'clk_prepare_enable',
            r'clk_disable_unprepare',
            r'clk_get',
            r'clk_put',
            r'clk_set_rate',
            r'clk_get_rate'
        ],
        'regulator_management': [
            r'regulator_enable',
            r'regulator_disable',
            r'regulator_get',
            r'regulator_put',
            r'regulator_set_voltage',
            r'regulator_get_voltage'
        ]
    }
    
    # Device tree patterns
    DEVICE_TREE_PATTERNS = {
        'dt_bindings': [
            r'of_match_table',
            r'\.of_match_table\s*=',
            r'of_device_id',
            r'MODULE_DEVICE_TABLE\s*\(\s*of\s*,',
            r'of_match_device',
            r'of_device_get_match_data'
        ],
        'property_parsing': [
            r'of_property_read_u32',
            r'of_property_read_u64',
            r'of_property_read_string',
            r'of_property_read_bool',
            r'of_property_count_',
            r'of_get_property',
            r'of_find_property',
            r'device_property_read_'
        ],
        'node_handling': [
            r'of_get_child_by_name',
            r'of_get_next_child',
            r'of_node_get',
            r'of_node_put',
            r'for_each_child_of_node',
            r'for_each_available_child_of_node'
        ],
        'resource_parsing': [
            r'of_iomap',
            r'of_address_to_resource',
            r'of_irq_get',
            r'of_irq_to_resource',
            r'platform_get_resource_byname',
            r'devm_ioremap_resource'
        ],
        'gpio_dt': [
            r'of_get_named_gpio',
            r'of_gpio_count',
            r'devm_gpiod_get',
            r'gpiod_get_from_of_node'
        ]
    }
    
    # Interrupt handling patterns
    INTERRUPT_PATTERNS = {
        'basic_irq': [
            r'request_irq',
            r'free_irq',
            r'devm_request_irq',
            r'enable_irq',
            r'disable_irq'
        ],
        'threaded_irq': [
            r'request_threaded_irq',
            r'devm_request_threaded_irq',
            r'IRQ_WAKE_THREAD',
            r'irq_wake_thread'
        ],
        'shared_irq': [
            r'IRQF_SHARED',
            r'IRQF_PROBE_SHARED'
        ],
        'irq_flags': [
            r'IRQF_TRIGGER_RISING',
            r'IRQF_TRIGGER_FALLING',
            r'IRQF_TRIGGER_HIGH',
            r'IRQF_TRIGGER_LOW',
            r'IRQF_ONESHOT',
            r'IRQF_NO_SUSPEND',
            r'IRQF_EARLY_RESUME'
        ],
        'irq_management': [
            r'irq_set_irq_wake',
            r'enable_irq_wake',
            r'disable_irq_wake',
            r'irq_set_status_flags',
            r'irq_clear_status_flags'
        ],
        'tasklet_workqueue': [
            r'tasklet_init',
            r'tasklet_schedule',
            r'INIT_WORK',
            r'schedule_work',
            r'queue_work',
            r'create_workqueue',
            r'create_singlethread_workqueue'
        ]
    }
    
    def __init__(self, config: Optional[AdvancedFeaturesConfiguration] = None):
        """Initialize the advanced features analyzer."""
        self.config = config or AdvancedFeaturesConfiguration(
            feature_types=[
                AdvancedFeatureType.POWER_MANAGEMENT,
                AdvancedFeatureType.DEVICE_TREE,
                AdvancedFeatureType.INTERRUPT_HANDLING
            ]
        )
    
    @property
    def name(self) -> str:
        """Return the name of this analyzer."""
        return "advanced_features_analyzer"
    
    @property
    def version(self) -> str:
        """Return the version of this analyzer."""
        return "1.0.0"
    
    def analyze(self, source_files: List[str], config: Dict[str, Any]) -> AnalysisResult:
        """
        Analyze source files for advanced driver features.
        
        Args:
            source_files: List of source file paths to analyze
            config: Additional configuration parameters
            
        Returns:
            AnalysisResult with advanced features findings and metrics
        """
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # Copy source files to temp directory
                temp_source_files = []
                for source_file in source_files:
                    if os.path.exists(source_file):
                        dest_path = os.path.join(temp_dir, os.path.basename(source_file))
                        shutil.copy2(source_file, dest_path)
                        temp_source_files.append(dest_path)
                
                if not temp_source_files:
                    return AnalysisResult(
                        analyzer=self.name,
                        status=AnalysisStatus.FAILURE,
                        findings=[Finding(
                            type="advanced_features_error",
                            severity=Severity.CRITICAL,
                            file="",
                            line=0,
                            column=0,
                            message="No valid source files provided for advanced features analysis",
                            recommendation="Ensure source files exist and are accessible"
                        )],
                        metrics={"advanced_features_attempted": False},
                        score=0.0
                    )
                
                # Run advanced features analysis
                findings, metrics = self._run_advanced_features_analysis(temp_dir, temp_source_files)
                
                # Determine overall status
                # For advanced features, findings are positive (INFO level), so SUCCESS is appropriate
                if any(f.severity == Severity.CRITICAL for f in findings):
                    status = AnalysisStatus.FAILURE
                elif any(f.severity in [Severity.HIGH, Severity.MEDIUM] for f in findings):
                    status = AnalysisStatus.WARNING
                else:
                    status = AnalysisStatus.SUCCESS
                
                # Calculate score based on detected features
                score = self._calculate_advanced_features_score(findings, metrics)
                
                return AnalysisResult(
                    analyzer=self.name,
                    status=status,
                    findings=findings,
                    metrics=metrics,
                    score=score
                )
                
        except Exception as e:
            return AnalysisResult(
                analyzer=self.name,
                status=AnalysisStatus.FAILURE,
                findings=[Finding(
                    type="advanced_features_error",
                    severity=Severity.CRITICAL,
                    file="",
                    line=0,
                    column=0,
                    message=f"Advanced features analysis failed: {str(e)}",
                    recommendation="Check system configuration and file accessibility"
                )],
                metrics={"advanced_features_attempted": False, "error": str(e)},
                score=0.0
            )
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate the configuration for this analyzer.
        
        Args:
            config: Configuration to validate
            
        Returns:
            True if configuration is valid, False otherwise
        """
        try:
            if 'timeout' in config and not isinstance(config['timeout'], int):
                return False
            
            if 'power_mgmt_weight' in config:
                weight = config['power_mgmt_weight']
                if not isinstance(weight, (int, float)) or weight < 0 or weight > 1:
                    return False
            
            if 'device_tree_weight' in config:
                weight = config['device_tree_weight']
                if not isinstance(weight, (int, float)) or weight < 0 or weight > 1:
                    return False
            
            if 'interrupt_weight' in config:
                weight = config['interrupt_weight']
                if not isinstance(weight, (int, float)) or weight < 0 or weight > 1:
                    return False
            
            return True
        except Exception:
            return False 
   
    def _run_advanced_features_analysis(self, temp_dir: str, source_files: List[str]) -> Tuple[List[Finding], Dict[str, Any]]:
        """Run comprehensive advanced features analysis."""
        all_findings = []
        metrics = {
            "advanced_features_attempted": True,
            "feature_types": [ft.value for ft in self.config.feature_types],
            "total_checks": 0,
            "successful_checks": 0,
            "detected_features": {},
            "feature_scores": {}
        }
        
        # Run each configured feature type analysis
        for feature_type in self.config.feature_types:
            if feature_type == AdvancedFeatureType.ALL:
                # Run all feature types
                for ft in [AdvancedFeatureType.POWER_MANAGEMENT, AdvancedFeatureType.DEVICE_TREE, 
                          AdvancedFeatureType.INTERRUPT_HANDLING]:
                    findings, feature_metrics = self._run_feature_analysis(temp_dir, source_files, ft)
                    if findings is not None:
                        all_findings.extend(findings)
                        metrics["detected_features"][ft.value] = feature_metrics
                        metrics["successful_checks"] += 1
                    metrics["total_checks"] += 1
            else:
                findings, feature_metrics = self._run_feature_analysis(temp_dir, source_files, feature_type)
                if findings is not None:
                    all_findings.extend(findings)
                    metrics["detected_features"][feature_type.value] = feature_metrics
                    metrics["successful_checks"] += 1
                metrics["total_checks"] += 1
        
        # Calculate feature scores
        metrics["feature_scores"] = self._calculate_feature_scores(metrics["detected_features"])
        
        return all_findings, metrics
    
    def _run_feature_analysis(self, temp_dir: str, source_files: List[str], feature_type: AdvancedFeatureType) -> Tuple[List[Finding], Dict[str, Any]]:
        """Run analysis for a specific advanced feature type."""
        try:
            if feature_type == AdvancedFeatureType.POWER_MANAGEMENT:
                return self._analyze_power_management(source_files)
            elif feature_type == AdvancedFeatureType.DEVICE_TREE:
                return self._analyze_device_tree_integration(source_files)
            elif feature_type == AdvancedFeatureType.INTERRUPT_HANDLING:
                return self._analyze_interrupt_handling(source_files)
            else:
                return [], {}
                
        except Exception as e:
            error_finding = Finding(
                type=f"{feature_type.value}_error",
                severity=Severity.LOW,
                file="",
                line=0,
                column=0,
                message=f"Advanced feature {feature_type.value} analysis failed: {str(e)}",
                recommendation="Check file format and system configuration"
            )
            return [error_finding], {"error": str(e)}
    
    def _analyze_power_management(self, source_files: List[str]) -> Tuple[List[Finding], Dict[str, Any]]:
        """Analyze power management features implementation."""
        findings = []
        metrics = {
            "suspend_resume_found": False,
            "runtime_pm_found": False,
            "power_states_found": False,
            "clock_management_found": False,
            "regulator_management_found": False,
            "power_mgmt_score": 0.0,
            "detected_patterns": []
        }
        
        for source_file in source_files:
            try:
                with open(source_file, 'r') as f:
                    content = f.read()
                
                file_basename = os.path.basename(source_file)
                
                # Check for suspend/resume implementation
                suspend_resume_patterns = self._find_patterns(content, self.POWER_MGMT_PATTERNS['suspend_resume'])
                if suspend_resume_patterns:
                    metrics["suspend_resume_found"] = True
                    metrics["detected_patterns"].extend(suspend_resume_patterns)
                    findings.append(Finding(
                        type="power_mgmt_suspend_resume",
                        severity=Severity.INFO,
                        file=file_basename,
                        line=suspend_resume_patterns[0]['line'],
                        column=0,
                        message="Suspend/resume power management implementation detected",
                        recommendation="Ensure proper error handling and resource management in suspend/resume callbacks"
                    ))
                
                # Check for runtime PM implementation
                runtime_pm_patterns = self._find_patterns(content, self.POWER_MGMT_PATTERNS['runtime_pm'])
                if runtime_pm_patterns:
                    metrics["runtime_pm_found"] = True
                    metrics["detected_patterns"].extend(runtime_pm_patterns)
                    findings.append(Finding(
                        type="power_mgmt_runtime_pm",
                        severity=Severity.INFO,
                        file=file_basename,
                        line=runtime_pm_patterns[0]['line'],
                        column=0,
                        message="Runtime power management implementation detected",
                        recommendation="Verify proper runtime PM reference counting and error handling"
                    ))
                
                # Check for power state management
                power_states_patterns = self._find_patterns(content, self.POWER_MGMT_PATTERNS['power_states'])
                if power_states_patterns:
                    metrics["power_states_found"] = True
                    metrics["detected_patterns"].extend(power_states_patterns)
                    findings.append(Finding(
                        type="power_mgmt_power_states",
                        severity=Severity.INFO,
                        file=file_basename,
                        line=power_states_patterns[0]['line'],
                        column=0,
                        message="Advanced power state management detected",
                        recommendation="Ensure all power states are properly handled and tested"
                    ))
                
                # Check for clock management
                clock_patterns = self._find_patterns(content, self.POWER_MGMT_PATTERNS['clock_management'])
                if clock_patterns:
                    metrics["clock_management_found"] = True
                    metrics["detected_patterns"].extend(clock_patterns)
                    findings.append(Finding(
                        type="power_mgmt_clock_management",
                        severity=Severity.INFO,
                        file=file_basename,
                        line=clock_patterns[0]['line'],
                        column=0,
                        message="Clock management for power efficiency detected",
                        recommendation="Verify proper clock enable/disable sequencing and error handling"
                    ))
                
                # Check for regulator management
                regulator_patterns = self._find_patterns(content, self.POWER_MGMT_PATTERNS['regulator_management'])
                if regulator_patterns:
                    metrics["regulator_management_found"] = True
                    metrics["detected_patterns"].extend(regulator_patterns)
                    findings.append(Finding(
                        type="power_mgmt_regulator_management",
                        severity=Severity.INFO,
                        file=file_basename,
                        line=regulator_patterns[0]['line'],
                        column=0,
                        message="Regulator management for power control detected",
                        recommendation="Ensure proper regulator enable/disable sequencing and voltage settings"
                    ))
                
            except Exception as e:
                findings.append(Finding(
                    type="power_mgmt_analysis_error",
                    severity=Severity.LOW,
                    file=os.path.basename(source_file),
                    line=0,
                    column=0,
                    message=f"Power management analysis failed: {str(e)}",
                    recommendation="Check file format and accessibility"
                ))
        
        # Calculate power management score
        power_features = [
            metrics["suspend_resume_found"],
            metrics["runtime_pm_found"], 
            metrics["power_states_found"],
            metrics["clock_management_found"],
            metrics["regulator_management_found"]
        ]
        metrics["power_mgmt_score"] = sum(power_features) / len(power_features)
        
        return findings, metrics
    
    def _analyze_device_tree_integration(self, source_files: List[str]) -> Tuple[List[Finding], Dict[str, Any]]:
        """Analyze device tree integration implementation."""
        findings = []
        metrics = {
            "dt_bindings_found": False,
            "property_parsing_found": False,
            "node_handling_found": False,
            "resource_parsing_found": False,
            "gpio_dt_found": False,
            "device_tree_score": 0.0,
            "detected_patterns": []
        }
        
        for source_file in source_files:
            try:
                with open(source_file, 'r') as f:
                    content = f.read()
                
                file_basename = os.path.basename(source_file)
                
                # Check for device tree bindings
                dt_bindings_patterns = self._find_patterns(content, self.DEVICE_TREE_PATTERNS['dt_bindings'])
                if dt_bindings_patterns:
                    metrics["dt_bindings_found"] = True
                    metrics["detected_patterns"].extend(dt_bindings_patterns)
                    findings.append(Finding(
                        type="device_tree_bindings",
                        severity=Severity.INFO,
                        file=file_basename,
                        line=dt_bindings_patterns[0]['line'],
                        column=0,
                        message="Device tree bindings implementation detected",
                        recommendation="Ensure device tree bindings are properly documented and tested"
                    ))
                
                # Check for property parsing
                property_patterns = self._find_patterns(content, self.DEVICE_TREE_PATTERNS['property_parsing'])
                if property_patterns:
                    metrics["property_parsing_found"] = True
                    metrics["detected_patterns"].extend(property_patterns)
                    findings.append(Finding(
                        type="device_tree_property_parsing",
                        severity=Severity.INFO,
                        file=file_basename,
                        line=property_patterns[0]['line'],
                        column=0,
                        message="Device tree property parsing implementation detected",
                        recommendation="Validate all parsed properties and handle missing properties gracefully"
                    ))
                
                # Check for node handling
                node_patterns = self._find_patterns(content, self.DEVICE_TREE_PATTERNS['node_handling'])
                if node_patterns:
                    metrics["node_handling_found"] = True
                    metrics["detected_patterns"].extend(node_patterns)
                    findings.append(Finding(
                        type="device_tree_node_handling",
                        severity=Severity.INFO,
                        file=file_basename,
                        line=node_patterns[0]['line'],
                        column=0,
                        message="Advanced device tree node handling detected",
                        recommendation="Ensure proper node reference counting with of_node_get/put"
                    ))
                
                # Check for resource parsing
                resource_patterns = self._find_patterns(content, self.DEVICE_TREE_PATTERNS['resource_parsing'])
                if resource_patterns:
                    metrics["resource_parsing_found"] = True
                    metrics["detected_patterns"].extend(resource_patterns)
                    findings.append(Finding(
                        type="device_tree_resource_parsing",
                        severity=Severity.INFO,
                        file=file_basename,
                        line=resource_patterns[0]['line'],
                        column=0,
                        message="Device tree resource parsing implementation detected",
                        recommendation="Verify proper resource mapping and error handling for missing resources"
                    ))
                
                # Check for GPIO device tree integration
                gpio_patterns = self._find_patterns(content, self.DEVICE_TREE_PATTERNS['gpio_dt'])
                if gpio_patterns:
                    metrics["gpio_dt_found"] = True
                    metrics["detected_patterns"].extend(gpio_patterns)
                    findings.append(Finding(
                        type="device_tree_gpio_integration",
                        severity=Severity.INFO,
                        file=file_basename,
                        line=gpio_patterns[0]['line'],
                        column=0,
                        message="GPIO device tree integration detected",
                        recommendation="Ensure proper GPIO descriptor handling and error checking"
                    ))
                
            except Exception as e:
                findings.append(Finding(
                    type="device_tree_analysis_error",
                    severity=Severity.LOW,
                    file=os.path.basename(source_file),
                    line=0,
                    column=0,
                    message=f"Device tree analysis failed: {str(e)}",
                    recommendation="Check file format and accessibility"
                ))
        
        # Calculate device tree score
        dt_features = [
            metrics["dt_bindings_found"],
            metrics["property_parsing_found"],
            metrics["node_handling_found"],
            metrics["resource_parsing_found"],
            metrics["gpio_dt_found"]
        ]
        metrics["device_tree_score"] = sum(dt_features) / len(dt_features)
        
        return findings, metrics
    
    def _analyze_interrupt_handling(self, source_files: List[str]) -> Tuple[List[Finding], Dict[str, Any]]:
        """Analyze interrupt handling sophistication."""
        findings = []
        metrics = {
            "basic_irq_found": False,
            "threaded_irq_found": False,
            "shared_irq_found": False,
            "irq_flags_found": False,
            "irq_management_found": False,
            "tasklet_workqueue_found": False,
            "interrupt_score": 0.0,
            "detected_patterns": []
        }
        
        for source_file in source_files:
            try:
                with open(source_file, 'r') as f:
                    content = f.read()
                
                file_basename = os.path.basename(source_file)
                
                # Check for basic IRQ handling
                basic_irq_patterns = self._find_patterns(content, self.INTERRUPT_PATTERNS['basic_irq'])
                if basic_irq_patterns:
                    metrics["basic_irq_found"] = True
                    metrics["detected_patterns"].extend(basic_irq_patterns)
                    findings.append(Finding(
                        type="interrupt_basic_handling",
                        severity=Severity.INFO,
                        file=file_basename,
                        line=basic_irq_patterns[0]['line'],
                        column=0,
                        message="Basic interrupt handling implementation detected",
                        recommendation="Consider using devm_request_irq for automatic cleanup"
                    ))
                
                # Check for threaded IRQ handling
                threaded_irq_patterns = self._find_patterns(content, self.INTERRUPT_PATTERNS['threaded_irq'])
                if threaded_irq_patterns:
                    metrics["threaded_irq_found"] = True
                    metrics["detected_patterns"].extend(threaded_irq_patterns)
                    findings.append(Finding(
                        type="interrupt_threaded_handling",
                        severity=Severity.INFO,
                        file=file_basename,
                        line=threaded_irq_patterns[0]['line'],
                        column=0,
                        message="Advanced threaded interrupt handling detected",
                        recommendation="Ensure proper synchronization between hard and threaded IRQ handlers"
                    ))
                
                # Check for shared IRQ support
                shared_irq_patterns = self._find_patterns(content, self.INTERRUPT_PATTERNS['shared_irq'])
                if shared_irq_patterns:
                    metrics["shared_irq_found"] = True
                    metrics["detected_patterns"].extend(shared_irq_patterns)
                    findings.append(Finding(
                        type="interrupt_shared_handling",
                        severity=Severity.INFO,
                        file=file_basename,
                        line=shared_irq_patterns[0]['line'],
                        column=0,
                        message="Shared interrupt handling support detected",
                        recommendation="Verify IRQ handler returns IRQ_HANDLED only when interrupt is actually handled"
                    ))
                
                # Check for advanced IRQ flags
                irq_flags_patterns = self._find_patterns(content, self.INTERRUPT_PATTERNS['irq_flags'])
                if irq_flags_patterns:
                    metrics["irq_flags_found"] = True
                    metrics["detected_patterns"].extend(irq_flags_patterns)
                    findings.append(Finding(
                        type="interrupt_advanced_flags",
                        severity=Severity.INFO,
                        file=file_basename,
                        line=irq_flags_patterns[0]['line'],
                        column=0,
                        message="Advanced interrupt flags configuration detected",
                        recommendation="Ensure IRQ flags match hardware characteristics and system requirements"
                    ))
                
                # Check for IRQ management
                irq_mgmt_patterns = self._find_patterns(content, self.INTERRUPT_PATTERNS['irq_management'])
                if irq_mgmt_patterns:
                    metrics["irq_management_found"] = True
                    metrics["detected_patterns"].extend(irq_mgmt_patterns)
                    findings.append(Finding(
                        type="interrupt_management",
                        severity=Severity.INFO,
                        file=file_basename,
                        line=irq_mgmt_patterns[0]['line'],
                        column=0,
                        message="Advanced interrupt management features detected",
                        recommendation="Verify proper wake-up source configuration and power management integration"
                    ))
                
                # Check for tasklet/workqueue usage
                tasklet_patterns = self._find_patterns(content, self.INTERRUPT_PATTERNS['tasklet_workqueue'])
                if tasklet_patterns:
                    metrics["tasklet_workqueue_found"] = True
                    metrics["detected_patterns"].extend(tasklet_patterns)
                    findings.append(Finding(
                        type="interrupt_deferred_work",
                        severity=Severity.INFO,
                        file=file_basename,
                        line=tasklet_patterns[0]['line'],
                        column=0,
                        message="Deferred work handling (tasklets/workqueues) detected",
                        recommendation="Ensure proper synchronization and cleanup of deferred work"
                    ))
                
            except Exception as e:
                findings.append(Finding(
                    type="interrupt_analysis_error",
                    severity=Severity.LOW,
                    file=os.path.basename(source_file),
                    line=0,
                    column=0,
                    message=f"Interrupt handling analysis failed: {str(e)}",
                    recommendation="Check file format and accessibility"
                ))
        
        # Calculate interrupt handling score
        interrupt_features = [
            metrics["basic_irq_found"],
            metrics["threaded_irq_found"],
            metrics["shared_irq_found"],
            metrics["irq_flags_found"],
            metrics["irq_management_found"],
            metrics["tasklet_workqueue_found"]
        ]
        metrics["interrupt_score"] = sum(interrupt_features) / len(interrupt_features)
        
        return findings, metrics
    
    def _find_patterns(self, content: str, patterns: List[str]) -> List[Dict[str, Any]]:
        """Find pattern matches in content with line numbers."""
        matches = []
        lines = content.split('\n')
        
        for pattern in patterns:
            regex = re.compile(pattern, re.IGNORECASE)
            for line_num, line in enumerate(lines, 1):
                if regex.search(line):
                    matches.append({
                        'pattern': pattern,
                        'line': line_num,
                        'matched_text': line.strip()
                    })
        
        return matches
    
    def _calculate_feature_scores(self, detected_features: Dict[str, Dict[str, Any]]) -> Dict[str, float]:
        """Calculate individual feature type scores."""
        scores = {}
        
        for feature_type, metrics in detected_features.items():
            if feature_type == "power_management":
                scores[feature_type] = metrics.get("power_mgmt_score", 0.0)
            elif feature_type == "device_tree":
                scores[feature_type] = metrics.get("device_tree_score", 0.0)
            elif feature_type == "interrupt_handling":
                scores[feature_type] = metrics.get("interrupt_score", 0.0)
            else:
                scores[feature_type] = 0.0
        
        return scores
    
    def _calculate_advanced_features_score(self, findings: List[Finding], metrics: Dict[str, Any]) -> float:
        """Calculate overall advanced features score."""
        if not metrics.get("detected_features"):
            return 0.0
        
        feature_scores = metrics.get("feature_scores", {})
        
        # Apply weights to different feature types
        weighted_score = 0.0
        total_weight = 0.0
        
        if "power_management" in feature_scores:
            weighted_score += feature_scores["power_management"] * self.config.power_mgmt_weight
            total_weight += self.config.power_mgmt_weight
        
        if "device_tree" in feature_scores:
            weighted_score += feature_scores["device_tree"] * self.config.device_tree_weight
            total_weight += self.config.device_tree_weight
        
        if "interrupt_handling" in feature_scores:
            weighted_score += feature_scores["interrupt_handling"] * self.config.interrupt_weight
            total_weight += self.config.interrupt_weight
        
        if total_weight > 0:
            return (weighted_score / total_weight) * 100.0
        else:
            return 0.0