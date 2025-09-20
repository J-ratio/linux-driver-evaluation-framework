"""
Data models for the Linux Driver Evaluation Framework.

This module contains the core data models used throughout the evaluation system,
including request models, result models, and report models with JSON serialization
and validation capabilities.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from enum import Enum
import json
import re

from ..core.interfaces import Severity


class AnalysisDepth(Enum):
    """Analysis depth levels for evaluation requests."""
    BASIC = "basic"
    STANDARD = "standard"
    COMPREHENSIVE = "comprehensive"


class AnalysisStatus(Enum):
    """Status of analysis execution."""
    SUCCESS = "success"
    FAILURE = "failure"
    WARNING = "warning"


class Grade(Enum):
    """Overall quality grades."""
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


@dataclass
class SourceFile:
    """Represents a source code file in an evaluation request."""
    filename: str
    content: str
    size: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SourceFile':
        """Create instance from dictionary."""
        return cls(**data)
    
    def validate(self) -> List[str]:
        """Validate the source file data."""
        errors = []
        
        if not self.filename:
            errors.append("Filename cannot be empty")
        
        if not self.filename.endswith('.c'):
            errors.append("File must have .c extension")
        
        if not self.content:
            errors.append("File content cannot be empty")
        
        if self.size != len(self.content):
            errors.append("File size does not match content length")
        
        if self.size > 1024 * 1024:  # 1MB limit
            errors.append("File size exceeds 1MB limit")
        
        return errors


@dataclass
class EvaluationConfiguration:
    """Configuration settings for an evaluation request."""
    kernel_version: str = "5.15"
    target_architecture: str = "x86_64"
    analysis_depth: AnalysisDepth = AnalysisDepth.STANDARD
    custom_rules: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "kernel_version": self.kernel_version,
            "target_architecture": self.target_architecture,
            "analysis_depth": self.analysis_depth.value,
            "custom_rules": self.custom_rules
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EvaluationConfiguration':
        """Create instance from dictionary."""
        return cls(
            kernel_version=data.get("kernel_version", "5.15"),
            target_architecture=data.get("target_architecture", "x86_64"),
            analysis_depth=AnalysisDepth(data.get("analysis_depth", "standard")),
            custom_rules=data.get("custom_rules", {})
        )
    
    def validate(self) -> List[str]:
        """Validate the configuration data."""
        errors = []
        
        # Validate kernel version format (e.g., "5.15", "6.1")
        if not re.match(r'^\d+\.\d+$', self.kernel_version):
            errors.append("Invalid kernel version format (expected: X.Y)")
        
        # Validate target architecture
        valid_architectures = ["x86_64", "arm64", "arm", "riscv64"]
        if self.target_architecture not in valid_architectures:
            errors.append(f"Invalid target architecture. Must be one of: {', '.join(valid_architectures)}")
        
        return errors


@dataclass
class EvaluationRequest:
    """Represents a request to evaluate Linux driver code."""
    id: str
    source_files: List[SourceFile]
    timestamp: datetime = field(default_factory=datetime.now)
    configuration: EvaluationConfiguration = field(default_factory=EvaluationConfiguration)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "source_files": [sf.to_dict() for sf in self.source_files],
            "configuration": self.configuration.to_dict()
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EvaluationRequest':
        """Create instance from dictionary."""
        return cls(
            id=data["id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            source_files=[SourceFile.from_dict(sf) for sf in data["source_files"]],
            configuration=EvaluationConfiguration.from_dict(data.get("configuration", {}))
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> 'EvaluationRequest':
        """Create instance from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)
    
    def validate(self) -> List[str]:
        """Validate the evaluation request."""
        errors = []
        
        if not self.id:
            errors.append("Request ID cannot be empty")
        
        if not self.source_files:
            errors.append("At least one source file is required")
        
        # Validate each source file
        for i, source_file in enumerate(self.source_files):
            file_errors = source_file.validate()
            for error in file_errors:
                errors.append(f"Source file {i+1}: {error}")
        
        # Validate configuration
        config_errors = self.configuration.validate()
        for error in config_errors:
            errors.append(f"Configuration: {error}")
        
        return errors


@dataclass
class Finding:
    """Represents a single finding from static analysis."""
    type: str
    severity: Severity
    file: str
    line: int
    column: int
    message: str
    recommendation: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "type": self.type,
            "severity": self.severity.value,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "recommendation": self.recommendation
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding':
        """Create instance from dictionary."""
        return cls(
            type=data["type"],
            severity=Severity(data["severity"]),
            file=data["file"],
            line=data["line"],
            column=data["column"],
            message=data["message"],
            recommendation=data.get("recommendation", "")
        )


@dataclass
class AnalysisResult:
    """Represents the result from a single analyzer."""
    analyzer: str
    status: AnalysisStatus
    findings: List[Finding] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "analyzer": self.analyzer,
            "status": self.status.value,
            "findings": [f.to_dict() for f in self.findings],
            "metrics": self.metrics
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AnalysisResult':
        """Create instance from dictionary."""
        return cls(
            analyzer=data["analyzer"],
            status=AnalysisStatus(data["status"]),
            findings=[Finding.from_dict(f) for f in data.get("findings", [])],
            metrics=data.get("metrics", {})
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> 'AnalysisResult':
        """Create instance from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)
    
    def validate(self) -> List[str]:
        """Validate the analysis result."""
        errors = []
        
        if not self.analyzer:
            errors.append("Analyzer name cannot be empty")
        
        # Validate findings
        for i, finding in enumerate(self.findings):
            if not finding.type:
                errors.append(f"Finding {i+1}: type cannot be empty")
            if not finding.message:
                errors.append(f"Finding {i+1}: message cannot be empty")
            if finding.line < 0:
                errors.append(f"Finding {i+1}: line number must be non-negative")
            if finding.column < 0:
                errors.append(f"Finding {i+1}: column number must be non-negative")
        
        return errors


@dataclass
class DimensionScores:
    """Scores for each evaluation dimension."""
    correctness: float
    security: float
    code_quality: float
    performance: float
    advanced_features: float
    
    def to_dict(self) -> Dict[str, float]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, float]) -> 'DimensionScores':
        """Create instance from dictionary."""
        return cls(**data)
    
    def validate(self) -> List[str]:
        """Validate dimension scores."""
        errors = []
        
        for field_name, score in asdict(self).items():
            if not isinstance(score, (int, float)):
                errors.append(f"{field_name} score must be a number")
            elif score < 0.0 or score > 100.0:
                errors.append(f"{field_name} score must be between 0.0 and 100.0")
        
        return errors


@dataclass
class EvaluationSummary:
    """Summary statistics for an evaluation."""
    total_issues: int
    critical_issues: int
    compilation_status: bool
    
    def to_dict(self) -> Dict[str, Union[int, bool]]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Union[int, bool]]) -> 'EvaluationSummary':
        """Create instance from dictionary."""
        return cls(**data)
    
    def validate(self) -> List[str]:
        """Validate summary data."""
        errors = []
        
        if self.total_issues < 0:
            errors.append("Total issues count cannot be negative")
        
        if self.critical_issues < 0:
            errors.append("Critical issues count cannot be negative")
        
        if self.critical_issues > self.total_issues:
            errors.append("Critical issues cannot exceed total issues")
        
        return errors


@dataclass
class EvaluationReport:
    """Comprehensive evaluation report containing all results and scores."""
    evaluation_id: str
    overall_score: float
    grade: Grade
    dimension_scores: DimensionScores
    summary: EvaluationSummary
    detailed_findings: List[Finding] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "evaluation_id": self.evaluation_id,
            "overall_score": self.overall_score,
            "grade": self.grade.value,
            "dimension_scores": self.dimension_scores.to_dict(),
            "summary": self.summary.to_dict(),
            "detailed_findings": [f.to_dict() for f in self.detailed_findings],
            "recommendations": self.recommendations
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EvaluationReport':
        """Create instance from dictionary."""
        return cls(
            evaluation_id=data["evaluation_id"],
            overall_score=data["overall_score"],
            grade=Grade(data["grade"]),
            dimension_scores=DimensionScores.from_dict(data["dimension_scores"]),
            summary=EvaluationSummary.from_dict(data["summary"]),
            detailed_findings=[Finding.from_dict(f) for f in data.get("detailed_findings", [])],
            recommendations=data.get("recommendations", [])
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> 'EvaluationReport':
        """Create instance from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)
    
    def validate(self) -> List[str]:
        """Validate the evaluation report."""
        errors = []
        
        if not self.evaluation_id:
            errors.append("Evaluation ID cannot be empty")
        
        if not isinstance(self.overall_score, (int, float)):
            errors.append("Overall score must be a number")
        elif self.overall_score < 0.0 or self.overall_score > 100.0:
            errors.append("Overall score must be between 0.0 and 100.0")
        
        # Validate dimension scores
        dimension_errors = self.dimension_scores.validate()
        for error in dimension_errors:
            errors.append(f"Dimension scores: {error}")
        
        # Validate summary
        summary_errors = self.summary.validate()
        for error in summary_errors:
            errors.append(f"Summary: {error}")
        
        # Validate findings
        for i, finding in enumerate(self.detailed_findings):
            if not finding.type:
                errors.append(f"Finding {i+1}: type cannot be empty")
            if not finding.message:
                errors.append(f"Finding {i+1}: message cannot be empty")
        
        return errors