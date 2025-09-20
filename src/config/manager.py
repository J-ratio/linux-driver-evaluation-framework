"""
Configuration management for the Linux Driver Evaluation Framework.

This module provides configuration loading, validation, and management
for analysis parameters and tool settings.
"""

import json
import os
from typing import Dict, Any, Optional
from pathlib import Path

from ..core.interfaces import ConfigurationManager


class DefaultConfigurationManager(ConfigurationManager):
    """Default implementation of configuration management."""
    
    def __init__(self, default_config_path: str = "config/default.json"):
        self.default_config_path = default_config_path
        self._config_cache: Optional[Dict[str, Any]] = None
        self._default_config = self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get the default configuration settings."""
        return {
            "system": {
                "max_file_size_mb": 10,
                "analysis_timeout_seconds": 300,
                "temp_dir": "/tmp/driver_eval",
                "log_level": "INFO"
            },
            "compilation": {
                "kernel_version": "5.15",
                "available_kernel_versions": [
                    "5.4", "5.10", "5.15", "6.1", "6.6"
                ],
                "kernel_version_configs": {
                    "5.4": {
                        "description": "Long Term Support (LTS) - Ubuntu 20.04 default",
                        "docker_image": "ubuntu:20.04",
                        "headers_package": "linux-headers-5.4.0-generic"
                    },
                    "5.15": {
                        "description": "Long Term Support (LTS) - Ubuntu 22.04 default", 
                        "docker_image": "ubuntu:22.04",
                        "headers_package": "linux-headers-generic"
                    },
                    "6.6": {
                        "description": "Long Term Support (LTS) - Latest",
                        "docker_image": "ubuntu:24.04", 
                        "headers_package": "linux-headers-generic"
                    }
                },
                "gcc_flags": ["-Wall", "-Wextra", "-Werror"],
            },
            "analyzers": {
                "correctness": {
                    "enabled": True,
                    "clang_tidy_checks": [
                        "clang-analyzer-*",
                        "bugprone-*",
                        "cert-*"
                    ],
                    "coccinelle_rules": "rules/kernel_api.cocci"
                },
                "security": {
                    "enabled": True,
                    "flawfinder_min_level": 2,
                    "smatch_enabled": True,
                    "dangerous_functions": [
                        "strcpy", "sprintf", "gets", "strcat"
                    ]
                },
                "code_quality": {
                    "enabled": True,
                    "checkpatch_strict": False,
                    "max_complexity": 15,
                    "min_documentation_coverage": 0.7
                },
                "performance": {
                    "enabled": True,
                    "complexity_analysis": True,
                    "memory_pattern_detection": True
                },
                "advanced_features": {
                    "enabled": True,
                    "power_management_patterns": True,
                    "device_tree_integration": True,
                    "interrupt_handling": True
                }
            },
            "scoring": {
                "weights": {
                    "correctness": 0.40,
                    "security": 0.25,
                    "code_quality": 0.20,
                    "performance": 0.10,
                    "advanced_features": 0.05
                },
                "grade_thresholds": {
                    "A": 90.0,
                    "B": 80.0,
                    "C": 70.0,
                    "D": 60.0,
                    "F": 0.0
                }
            },
            "reporting": {
                "formats": ["json", "html", "pdf"],
                "include_recommendations": True,
                "max_findings_per_type": 50
            }
        }
    
    def load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """Load configuration from file or return default settings."""
        if self._config_cache is not None:
            return self._config_cache
        
        config = self._default_config.copy()
        
        # Try to load from specified path or default path
        path_to_try = config_path or self.default_config_path
        
        if os.path.exists(path_to_try):
            try:
                with open(path_to_try, 'r') as f:
                    file_config = json.load(f)
                    config = self._merge_configs(config, file_config)
            except (json.JSONDecodeError, IOError) as e:
                print(f"Warning: Could not load config from {path_to_try}: {e}")
                print("Using default configuration")
        
        self._config_cache = config
        return config
    
    def save_config(self, config: Dict[str, Any], config_path: Optional[str] = None) -> bool:
        """Save configuration to file."""
        path_to_save = config_path or self.default_config_path
        
        try:
            # Ensure directory exists
            Path(path_to_save).parent.mkdir(parents=True, exist_ok=True)
            
            with open(path_to_save, 'w') as f:
                json.dump(config, f, indent=2)
            
            # Update cache
            self._config_cache = config
            return True
        except (IOError, TypeError) as e:
            print(f"Error saving config to {path_to_save}: {e}")
            return False
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate configuration structure and values."""
        required_sections = ["system", "analyzers", "scoring"]
        
        # Check required sections exist
        for section in required_sections:
            if section not in config:
                return False
        
        # Validate scoring weights sum to 1.0
        weights = config.get("scoring", {}).get("weights", {})
        if weights:
            total_weight = sum(weights.values())
            if abs(total_weight - 1.0) > 0.01:  # Allow small floating point errors
                return False
        
        # Validate system settings
        system_config = config.get("system", {})
        if "max_file_size_mb" in system_config:
            if not isinstance(system_config["max_file_size_mb"], (int, float)) or system_config["max_file_size_mb"] <= 0:
                return False
        
        # Validate kernel version selection
        compilation_config = config.get("compilation", {})
        if "kernel_version" in compilation_config:
            kernel_version = compilation_config["kernel_version"]
            available_versions = compilation_config.get("available_kernel_versions", [])
            if available_versions and kernel_version not in available_versions:
                return False
        
        return True
    
    def get_analyzer_config(self, analyzer_name: str) -> Dict[str, Any]:
        """Get configuration specific to an analyzer."""
        config = self.load_config()
        return config.get("analyzers", {}).get(analyzer_name, {})
    
    def get_kernel_version_config(self, kernel_version: Optional[str] = None) -> Dict[str, Any]:
        """Get configuration for a specific kernel version."""
        config = self.load_config()
        compilation_config = config.get("compilation", {})
        
        # Use provided version or default
        version = kernel_version or compilation_config.get("kernel_version", "5.15")
        
        # Get version-specific config
        version_configs = compilation_config.get("kernel_version_configs", {})
        version_config = version_configs.get(version, {})
        
        return {
            "version": version,
            "description": version_config.get("description", f"Kernel {version}"),
            "docker_image": version_config.get("docker_image", "ubuntu:22.04"),
            "headers_package": version_config.get("headers_package", "linux-headers-generic")
        }
    
    def get_available_kernel_versions(self) -> list:
        """Get list of available kernel versions."""
        config = self.load_config()
        return config.get("compilation", {}).get("available_kernel_versions", ["5.15"])
    
    def get_available_architectures(self) -> list:
        """Get list of available target architectures."""
        config = self.load_config()
        return config.get("compilation", {}).get("available_architectures", ["x86_64"])
    
    def get_architecture_config(self, architecture: Optional[str] = None) -> Dict[str, Any]:
        """Get configuration for a specific target architecture."""
        config = self.load_config()
        compilation_config = config.get("compilation", {})
        
        # Use provided architecture or default
        arch = architecture or compilation_config.get("target_architecture", "x86_64")
        
        # Get architecture-specific config
        cross_compile_toolchains = compilation_config.get("cross_compile_toolchains", {})
        arch_specific_headers = compilation_config.get("arch_specific_headers", {})
        
        arch_descriptions = {
            "x86_64": "Intel/AMD 64-bit (x86_64)",
            "arm64": "ARM 64-bit (AArch64)",
            "arm": "ARM 32-bit",
            "riscv64": "RISC-V 64-bit"
        }
        
        return {
            "architecture": arch,
            "description": arch_descriptions.get(arch, f"{arch} architecture"),
            "cross_compile_prefix": cross_compile_toolchains.get(arch, ""),
            "headers_package": arch_specific_headers.get(arch, "linux-headers-generic")
        }
    
    def _merge_configs(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively merge two configuration dictionaries."""
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        
        return result