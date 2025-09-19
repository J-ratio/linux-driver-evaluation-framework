"""
Core interfaces for the Linux Driver Evaluation Framework.

This module defines the base interfaces that all analyzers, result aggregators,
and scoring systems must implement to ensure consistent behavior across the system.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from enum import Enum
from dataclasses import dataclass


class AnalysisStatus(Enum):
    """Status of an analysis operation."""
    SUCCESS = "success"
    FAILURE = "failure"
    WARNING = "warning"


class Severity(Enum):
    """Severity levels for analysis findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Represents a single finding from an analyzer."""
    type: str
    severity: Severity
    file: str
    line: int
    column: int
    message: str
    recommendation: str


@dataclass
class AnalysisResult:
    """Result from a single analyzer."""
    analyzer: str
    status: AnalysisStatus
    findings: List[Finding]
    metrics: Dict[str, Any]
    score: float


class BaseAnalyzer(ABC):
    """Base interface for all code analyzers."""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Return the name of this analyzer."""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Return the version of this analyzer."""
        pass
    
    @abstractmethod
    def analyze(self, source_files: List[str], config: Dict[str, Any]) -> AnalysisResult:
        """
        Analyze the provided source files.
        
        Args:
            source_files: List of file paths to analyze
            config: Configuration parameters for the analysis
            
        Returns:
            AnalysisResult containing findings and metrics
        """
        pass
    
    @abstractmethod
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate the configuration for this analyzer.
        
        Args:
            config: Configuration to validate
            
        Returns:
            True if configuration is valid, False otherwise
        """
        pass


class ResultAggregator(ABC):
    """Interface for aggregating results from multiple analyzers."""
    
    @abstractmethod
    def aggregate(self, results: List[AnalysisResult]) -> Dict[str, Any]:
        """
        Aggregate results from multiple analyzers.
        
        Args:
            results: List of analysis results to aggregate
            
        Returns:
            Aggregated results dictionary
        """
        pass
    
    @abstractmethod
    def resolve_conflicts(self, results: List[AnalysisResult]) -> List[Finding]:
        """
        Resolve conflicts between overlapping findings from different analyzers.
        
        Args:
            results: List of analysis results with potential conflicts
            
        Returns:
            Deduplicated list of findings
        """
        pass


class ScoringSystem(ABC):
    """Interface for scoring and grading evaluation results."""
    
    @property
    @abstractmethod
    def weights(self) -> Dict[str, float]:
        """Return the scoring weights for different dimensions."""
        pass
    
    @abstractmethod
    def calculate_score(self, aggregated_results: Dict[str, Any]) -> float:
        """
        Calculate overall score from aggregated results.
        
        Args:
            aggregated_results: Aggregated analysis results
            
        Returns:
            Overall score (0.0 to 100.0)
        """
        pass
    
    @abstractmethod
    def assign_grade(self, score: float) -> str:
        """
        Assign letter grade based on score.
        
        Args:
            score: Overall score
            
        Returns:
            Letter grade (A, B, C, D, or F)
        """
        pass
    
    @abstractmethod
    def get_dimension_scores(self, aggregated_results: Dict[str, Any]) -> Dict[str, float]:
        """
        Get scores for individual evaluation dimensions.
        
        Args:
            aggregated_results: Aggregated analysis results
            
        Returns:
            Dictionary mapping dimension names to scores
        """
        pass


class ConfigurationManager(ABC):
    """Interface for managing system configuration."""
    
    @abstractmethod
    def load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Load configuration from file or default settings.
        
        Args:
            config_path: Optional path to configuration file
            
        Returns:
            Configuration dictionary
        """
        pass
    
    @abstractmethod
    def save_config(self, config: Dict[str, Any], config_path: Optional[str] = None) -> bool:
        """
        Save configuration to file.
        
        Args:
            config: Configuration dictionary to save
            config_path: Optional path to save configuration
            
        Returns:
            True if save was successful, False otherwise
        """
        pass
    
    @abstractmethod
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate configuration structure and values.
        
        Args:
            config: Configuration to validate
            
        Returns:
            True if configuration is valid, False otherwise
        """
        pass
    
    @abstractmethod
    def get_analyzer_config(self, analyzer_name: str) -> Dict[str, Any]:
        """
        Get configuration specific to an analyzer.
        
        Args:
            analyzer_name: Name of the analyzer
            
        Returns:
            Analyzer-specific configuration
        """
        pass