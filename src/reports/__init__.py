"""
Report generation module for the Linux Driver Evaluation Framework.

This module provides comprehensive report generation capabilities including
HTML, PDF, and JSON formats with detailed findings and recommendations.
"""

from .generator import ReportGenerator
from .templates import HTMLTemplate, PDFTemplate, JSONTemplate
from .summary import SummaryGenerator
from .integration import ReportingIntegration, ReportConfigurationManager

__all__ = [
    'ReportGenerator',
    'HTMLTemplate', 
    'PDFTemplate',
    'JSONTemplate',
    'SummaryGenerator',
    'ReportingIntegration',
    'ReportConfigurationManager'
]