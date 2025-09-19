"""
Linux Driver Evaluation Framework

A comprehensive system for evaluating the quality of Linux device driver code
through automated static analysis and compilation testing.
"""

__version__ = "1.0.0"
__author__ = "Linux Driver Evaluation Framework Team"

from .core.interfaces import (
    BaseAnalyzer,
    ResultAggregator,
    ScoringSystem,
    ConfigurationManager,
    AnalysisResult,
    Finding,
    AnalysisStatus,
    Severity
)

from .config.manager import DefaultConfigurationManager

__all__ = [
    "BaseAnalyzer",
    "ResultAggregator", 
    "ScoringSystem",
    "ConfigurationManager",
    "DefaultConfigurationManager",
    "AnalysisResult",
    "Finding",
    "AnalysisStatus",
    "Severity"
]