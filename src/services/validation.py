"""
Input validation and preprocessing services for the Linux Driver Evaluation Framework.

This module provides functionality to validate submitted C source code files
and detect Linux driver patterns to ensure the code is appropriate for evaluation.
"""

import re
import os
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

from src.models.evaluation import SourceFile


class ValidationError(Exception):
    """Exception raised when validation fails."""
    pass


class DriverType(Enum):
    """Types of Linux drivers that can be detected."""
    CHARACTER_DEVICE = "character_device"
    BLOCK_DEVICE = "block_device"
    NETWORK_DEVICE = "network_device"
    PCI_DEVICE = "pci_device"
    USB_DEVICE = "usb_device"
    PLATFORM_DEVICE = "platform_device"
    I2C_DEVICE = "i2c_device"
    SPI_DEVICE = "spi_device"
    GENERIC_MODULE = "generic_module"
    UNKNOWN = "unknown"


@dataclass
class ValidationResult:
    """Result of file validation and driver detection."""
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    driver_type: DriverType
    detected_features: List[str]
    complexity_score: int  # Basic complexity estimate (0-100)


class CSourceValidator:
    """Validates C source code files for basic syntax and structure."""
    
    # Common C syntax patterns
    C_KEYWORDS = {
        'auto', 'break', 'case', 'char', 'const', 'continue', 'default', 'do',
        'double', 'else', 'enum', 'extern', 'float', 'for', 'goto', 'if',
        'inline', 'int', 'long', 'register', 'restrict', 'return', 'short',
        'signed', 'sizeof', 'static', 'struct', 'switch', 'typedef', 'union',
        'unsigned', 'void', 'volatile', 'while'
    }
    
    # Dangerous functions that should be flagged
    DANGEROUS_FUNCTIONS = {
        'strcpy', 'strcat', 'sprintf', 'gets', 'scanf'
    }
    
    def __init__(self):
        """Initialize the validator."""
        self.errors = []
        self.warnings = []
    
    def validate_syntax(self, content: str) -> Tuple[bool, List[str], List[str]]:
        """
        Perform basic C syntax validation.
        
        Args:
            content: The C source code content
            
        Returns:
            Tuple of (is_valid, errors, warnings)
        """
        self.errors = []
        self.warnings = []
        
        # Check for basic C structure
        self._check_basic_structure(content)
        
        # Check for balanced braces, parentheses, brackets
        self._check_balanced_delimiters(content)
        
        # Check for dangerous functions
        self._check_dangerous_functions(content)
        
        # Check for common syntax issues
        self._check_common_issues(content)
        
        return len(self.errors) == 0, self.errors.copy(), self.warnings.copy()
    
    def _check_basic_structure(self, content: str) -> None:
        """Check for basic C file structure."""
        # Remove comments and strings to avoid false positives
        cleaned_content = self._remove_comments_and_strings(content)
        
        # Check for at least one function definition
        function_pattern = r'\w+\s+\w+\s*\([^)]*\)\s*\{'
        if not re.search(function_pattern, cleaned_content):
            self.warnings.append("No function definitions found")
        
        # Check for include statements (should have at least one)
        if not re.search(r'#include\s*[<"]', content):
            self.warnings.append("No include statements found")
    
    def _check_balanced_delimiters(self, content: str) -> None:
        """Check for balanced braces, parentheses, and brackets."""
        # Remove comments and strings
        cleaned_content = self._remove_comments_and_strings(content)
        
        # Count delimiters
        brace_count = 0
        paren_count = 0
        bracket_count = 0
        
        for char in cleaned_content:
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
            elif char == '(':
                paren_count += 1
            elif char == ')':
                paren_count -= 1
            elif char == '[':
                bracket_count += 1
            elif char == ']':
                bracket_count -= 1
            
            # Check for negative counts (closing before opening)
            if brace_count < 0:
                self.errors.append("Unmatched closing brace '}'")
                break
            if paren_count < 0:
                self.errors.append("Unmatched closing parenthesis ')'")
                break
            if bracket_count < 0:
                self.errors.append("Unmatched closing bracket ']'")
                break
        
        # Check final counts
        if brace_count > 0:
            self.errors.append(f"Unmatched opening braces: {brace_count}")
        elif brace_count < 0:
            self.errors.append(f"Unmatched closing braces: {abs(brace_count)}")
        
        if paren_count > 0:
            self.errors.append(f"Unmatched opening parentheses: {paren_count}")
        elif paren_count < 0:
            self.errors.append(f"Unmatched closing parentheses: {abs(paren_count)}")
        
        if bracket_count > 0:
            self.errors.append(f"Unmatched opening brackets: {bracket_count}")
        elif bracket_count < 0:
            self.errors.append(f"Unmatched closing brackets: {abs(bracket_count)}")
    
    def _check_dangerous_functions(self, content: str) -> None:
        """Check for usage of dangerous functions."""
        for func in self.DANGEROUS_FUNCTIONS:
            pattern = rf'\b{func}\s*\('
            matches = re.finditer(pattern, content)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                self.warnings.append(f"Dangerous function '{func}' used at line {line_num}")
    
    def _check_common_issues(self, content: str) -> None:
        """Check for common C programming issues."""
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Check for assignment in if conditions (common mistake)
            if re.search(r'if\s*\([^=]*=[^=]', line):
                self.warnings.append(f"Possible assignment in if condition at line {i}")
            
            # Check for missing semicolons (basic check)
            stripped = line.strip()
            if (stripped and not stripped.startswith('#') and not stripped.startswith('//') 
                and not stripped.startswith('/*') and not stripped.endswith(';') 
                and not stripped.endswith('{') and not stripped.endswith('}')
                and not any(keyword in stripped for keyword in ['if', 'else', 'for', 'while', 'switch', 'case', 'default'])):
                # This is a very basic check - real syntax checking would need a parser
                pass
    
    def _remove_comments_and_strings(self, content: str) -> str:
        """Remove comments and string literals to avoid false positives."""
        # Remove single-line comments
        content = re.sub(r'//.*$', '', content, flags=re.MULTILINE)
        
        # Remove multi-line comments
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        
        # Remove string literals
        content = re.sub(r'"([^"\\]|\\.)*"', '""', content)
        content = re.sub(r"'([^'\\]|\\.)*'", "''", content)
        
        return content


class LinuxDriverDetector:
    """Detects Linux driver patterns and features in C source code."""
    
    # Linux kernel headers that indicate driver code
    KERNEL_HEADERS = {
        'linux/module.h': 'basic_module',
        'linux/kernel.h': 'kernel_functions',
        'linux/init.h': 'init_cleanup',
        'linux/fs.h': 'filesystem',
        'linux/cdev.h': 'character_device',
        'linux/device.h': 'device_model',
        'linux/platform_device.h': 'platform_device',
        'linux/pci.h': 'pci_device',
        'linux/usb.h': 'usb_device',
        'linux/netdevice.h': 'network_device',
        'linux/blkdev.h': 'block_device',
        'linux/i2c.h': 'i2c_device',
        'linux/spi/spi.h': 'spi_device',
        'linux/interrupt.h': 'interrupt_handling',
        'linux/workqueue.h': 'workqueue',
        'linux/timer.h': 'timer',
        'linux/gpio.h': 'gpio',
        'linux/of.h': 'device_tree',
        'linux/pm.h': 'power_management'
    }
    
    # Driver type patterns
    DRIVER_PATTERNS = {
        DriverType.CHARACTER_DEVICE: [
            r'struct\s+file_operations',
            r'register_chrdev',
            r'alloc_chrdev_region',
            r'cdev_init',
            r'cdev_add'
        ],
        DriverType.BLOCK_DEVICE: [
            r'struct\s+block_device_operations',
            r'register_blkdev',
            r'blk_init_queue',
            r'add_disk'
        ],
        DriverType.NETWORK_DEVICE: [
            r'struct\s+net_device',
            r'alloc_netdev',
            r'register_netdev',
            r'netif_start_queue'
        ],
        DriverType.PCI_DEVICE: [
            r'struct\s+pci_driver',
            r'pci_register_driver',
            r'pci_enable_device',
            r'pci_request_regions'
        ],
        DriverType.USB_DEVICE: [
            r'struct\s+usb_driver',
            r'usb_register',
            r'usb_submit_urb',
            r'usb_alloc_urb'
        ],
        DriverType.PLATFORM_DEVICE: [
            r'struct\s+platform_driver',
            r'platform_driver_register',
            r'platform_get_resource',
            r'platform_device_register'
        ],
        DriverType.I2C_DEVICE: [
            r'struct\s+i2c_driver',
            r'i2c_add_driver',
            r'i2c_transfer',
            r'i2c_smbus_'
        ],
        DriverType.SPI_DEVICE: [
            r'struct\s+spi_driver',
            r'spi_register_driver',
            r'spi_sync',
            r'spi_write'
        ]
    }
    
    # Advanced features to detect
    ADVANCED_FEATURES = {
        'power_management': [
            r'\.suspend\s*=',
            r'\.resume\s*=',
            r'pm_runtime_',
            r'device_init_wakeup'
        ],
        'device_tree': [
            r'of_match_table',
            r'of_property_read',
            r'of_get_property',
            r'for_each_child_of_node'
        ],
        'interrupt_handling': [
            r'request_irq',
            r'free_irq',
            r'IRQ_HANDLED',
            r'irqreturn_t'
        ],
        'dma_operations': [
            r'dma_alloc_coherent',
            r'dma_map_single',
            r'dma_sync_',
            r'DMA_'
        ],
        'sysfs_interface': [
            r'device_create_file',
            r'sysfs_create_group',
            r'DEVICE_ATTR',
            r'show_\w+',
            r'store_\w+'
        ],
        'workqueue_usage': [
            r'create_workqueue',
            r'queue_work',
            r'INIT_WORK',
            r'flush_workqueue'
        ]
    }
    
    def detect_driver_type(self, content: str) -> DriverType:
        """
        Detect the type of Linux driver based on code patterns.
        
        Args:
            content: The C source code content
            
        Returns:
            Detected driver type
        """
        # Check for specific driver patterns
        for driver_type, patterns in self.DRIVER_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content):
                    return driver_type
        
        # Check if it's at least a generic kernel module
        if self._is_kernel_module(content):
            return DriverType.GENERIC_MODULE
        
        return DriverType.UNKNOWN
    
    def detect_features(self, content: str) -> List[str]:
        """
        Detect advanced features and capabilities in the driver code.
        
        Args:
            content: The C source code content
            
        Returns:
            List of detected features
        """
        detected_features = []
        
        # Check for kernel headers
        for header, feature in self.KERNEL_HEADERS.items():
            if re.search(rf'#include\s*[<"]{re.escape(header)}[>"]', content):
                detected_features.append(feature)
        
        # Check for advanced features
        for feature, patterns in self.ADVANCED_FEATURES.items():
            for pattern in patterns:
                if re.search(pattern, content):
                    detected_features.append(feature)
                    break  # Only add each feature once
        
        return detected_features
    
    def _is_kernel_module(self, content: str) -> bool:
        """Check if the code appears to be a kernel module."""
        # Look for basic module patterns
        module_patterns = [
            r'module_init\s*\(',
            r'module_exit\s*\(',
            r'MODULE_LICENSE\s*\(',
            r'MODULE_AUTHOR\s*\(',
            r'MODULE_DESCRIPTION\s*\(',
            r'__init\s+\w+',
            r'__exit\s+\w+'
        ]
        
        for pattern in module_patterns:
            if re.search(pattern, content):
                return True
        
        return False
    
    def calculate_complexity(self, content: str) -> int:
        """
        Calculate a basic complexity score for the driver code.
        
        Args:
            content: The C source code content
            
        Returns:
            Complexity score (0-100)
        """
        score = 0
        
        # Count functions
        function_count = len(re.findall(r'\w+\s+\w+\s*\([^)]*\)\s*\{', content))
        score += min(function_count * 5, 30)  # Max 30 points for functions
        
        # Count structures
        struct_count = len(re.findall(r'struct\s+\w+\s*\{', content))
        score += min(struct_count * 10, 20)  # Max 20 points for structures
        
        # Count control flow statements
        control_flow = len(re.findall(r'\b(if|for|while|switch|case)\b', content))
        score += min(control_flow * 2, 25)  # Max 25 points for control flow
        
        # Count lines of code (excluding comments and empty lines)
        lines = [line.strip() for line in content.split('\n')]
        code_lines = [line for line in lines if line and not line.startswith('//') and not line.startswith('/*')]
        score += min(len(code_lines) // 10, 25)  # Max 25 points for LOC
        
        return min(score, 100)


class ValidationService:
    """Simple validation service for web interface compatibility."""
    
    def __init__(self):
        """Initialize the validation service."""
        self.input_validator = InputValidator()
    
    def is_valid_driver_code(self, content: str) -> bool:
        """
        Simple check if content appears to be Linux driver code.
        
        Args:
            content: The C source code content
            
        Returns:
            True if it appears to be driver code, False otherwise
        """
        # Check for basic kernel module patterns
        kernel_patterns = [
            r'#include\s*[<"]linux/',
            r'module_init\s*\(',
            r'module_exit\s*\(',
            r'MODULE_LICENSE\s*\(',
            r'struct\s+\w+\s*\{',
            r'static\s+\w+',
            r'__init\s+',
            r'__exit\s+'
        ]
        
        for pattern in kernel_patterns:
            if re.search(pattern, content):
                return True
        
        return False


class InputValidator:
    """Main input validation and preprocessing service."""
    
    def __init__(self):
        """Initialize the validator with its components."""
        self.c_validator = CSourceValidator()
        self.driver_detector = LinuxDriverDetector()
    
    def validate_source_file(self, source_file: SourceFile) -> ValidationResult:
        """
        Validate a single source file.
        
        Args:
            source_file: The source file to validate
            
        Returns:
            ValidationResult with validation status and detected features
        """
        errors = []
        warnings = []
        
        # First validate the source file model itself
        model_errors = source_file.validate()
        errors.extend(model_errors)
        
        if errors:
            return ValidationResult(
                is_valid=False,
                errors=errors,
                warnings=warnings,
                driver_type=DriverType.UNKNOWN,
                detected_features=[],
                complexity_score=0
            )
        
        # Validate C syntax
        is_valid_c, c_errors, c_warnings = self.c_validator.validate_syntax(source_file.content)
        errors.extend(c_errors)
        warnings.extend(c_warnings)
        
        # Detect driver type and features
        driver_type = self.driver_detector.detect_driver_type(source_file.content)
        detected_features = self.driver_detector.detect_features(source_file.content)
        complexity_score = self.driver_detector.calculate_complexity(source_file.content)
        
        # Check if it looks like driver code
        if driver_type == DriverType.UNKNOWN and not detected_features:
            warnings.append("Code does not appear to contain Linux driver patterns")
        
        return ValidationResult(
            is_valid=is_valid_c and len(errors) == 0,
            errors=errors,
            warnings=warnings,
            driver_type=driver_type,
            detected_features=detected_features,
            complexity_score=complexity_score
        )
    
    def validate_source_files(self, source_files: List[SourceFile]) -> List[ValidationResult]:
        """
        Validate multiple source files.
        
        Args:
            source_files: List of source files to validate
            
        Returns:
            List of ValidationResult objects
        """
        return [self.validate_source_file(sf) for sf in source_files]
    
    def preprocess_for_analysis(self, source_files: List[SourceFile]) -> Dict[str, Any]:
        """
        Preprocess source files for analysis.
        
        Args:
            source_files: List of validated source files
            
        Returns:
            Dictionary containing preprocessing results and metadata
        """
        validation_results = self.validate_source_files(source_files)
        
        # Aggregate information
        all_features = set()
        driver_types = set()
        total_complexity = 0
        has_errors = False
        
        for result in validation_results:
            all_features.update(result.detected_features)
            driver_types.add(result.driver_type)
            total_complexity += result.complexity_score
            if not result.is_valid:
                has_errors = True
        
        # Determine primary driver type
        primary_driver_type = DriverType.UNKNOWN
        if driver_types:
            # Remove UNKNOWN if other types are present
            non_unknown_types = [dt for dt in driver_types if dt != DriverType.UNKNOWN]
            if non_unknown_types:
                primary_driver_type = non_unknown_types[0]  # Take the first non-unknown type
            else:
                primary_driver_type = DriverType.UNKNOWN
        
        return {
            'validation_results': validation_results,
            'is_valid': not has_errors,
            'primary_driver_type': primary_driver_type,
            'detected_features': list(all_features),
            'average_complexity': total_complexity / len(source_files) if source_files else 0,
            'file_count': len(source_files),
            'total_lines': sum(sf.content.count('\n') + 1 for sf in source_files)
        }