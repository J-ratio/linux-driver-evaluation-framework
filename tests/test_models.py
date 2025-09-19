"""
Unit tests for the evaluation data models.
"""

import unittest
import json
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from models.evaluation import (
    EvaluationRequest, AnalysisResult, EvaluationReport,
    SourceFile, EvaluationConfiguration, Finding, DimensionScores,
    EvaluationSummary, AnalysisDepth, Severity, AnalysisStatus, Grade
)


class TestSourceFile(unittest.TestCase):
    """Test cases for SourceFile model."""
    
    def test_valid_source_file(self):
        """Test creating a valid source file."""
        content = "#include <linux/module.h>\nstatic int __init test_init(void) { return 0; }"
        source_file = SourceFile(
            filename="test_driver.c",
            content=content,
            size=len(content)
        )
        
        errors = source_file.validate()
        self.assertEqual(len(errors), 0)
    
    def test_invalid_filename(self):
        """Test validation with invalid filename."""
        source_file = SourceFile(
            filename="test.txt",
            content="test content",
            size=12
        )
        
        errors = source_file.validate()
        self.assertIn("File must have .c extension", errors)
    
    def test_empty_content(self):
        """Test validation with empty content."""
        source_file = SourceFile(
            filename="test.c",
            content="",
            size=0
        )
        
        errors = source_file.validate()
        self.assertIn("File content cannot be empty", errors)
    
    def test_size_mismatch(self):
        """Test validation with size mismatch."""
        source_file = SourceFile(
            filename="test.c",
            content="test",
            size=10
        )
        
        errors = source_file.validate()
        self.assertIn("File size does not match content length", errors)
    
    def test_serialization(self):
        """Test JSON serialization and deserialization."""
        original = SourceFile(
            filename="test.c",
            content="test content",
            size=12
        )
        
        # Test to_dict and from_dict
        data = original.to_dict()
        restored = SourceFile.from_dict(data)
        
        self.assertEqual(original.filename, restored.filename)
        self.assertEqual(original.content, restored.content)
        self.assertEqual(original.size, restored.size)


class TestEvaluationRequest(unittest.TestCase):
    """Test cases for EvaluationRequest model."""
    
    def setUp(self):
        """Set up test data."""
        content = "#include <linux/module.h>\nstatic int __init test_init(void) { return 0; }"
        self.source_file = SourceFile(
            filename="test_driver.c",
            content=content,
            size=len(content)
        )
        
        self.config = EvaluationConfiguration(
            kernel_version="5.15",
            analysis_depth=AnalysisDepth.STANDARD
        )
        
        self.request = EvaluationRequest(
            id="test-123",
            timestamp=datetime.now(),
            source_files=[self.source_file],
            configuration=self.config
        )
    
    def test_valid_request(self):
        """Test creating a valid evaluation request."""
        errors = self.request.validate()
        if errors:
            print(f"Validation errors: {errors}")
        self.assertEqual(len(errors), 0)
    
    def test_empty_id(self):
        """Test validation with empty ID."""
        self.request.id = ""
        errors = self.request.validate()
        self.assertIn("Request ID cannot be empty", errors)
    
    def test_no_source_files(self):
        """Test validation with no source files."""
        self.request.source_files = []
        errors = self.request.validate()
        self.assertIn("At least one source file is required", errors)
    
    def test_json_serialization(self):
        """Test JSON serialization and deserialization."""
        # Test to_json and from_json
        json_str = self.request.to_json()
        restored = EvaluationRequest.from_json(json_str)
        
        self.assertEqual(self.request.id, restored.id)
        self.assertEqual(len(self.request.source_files), len(restored.source_files))
        self.assertEqual(self.request.source_files[0].filename, restored.source_files[0].filename)


class TestAnalysisResult(unittest.TestCase):
    """Test cases for AnalysisResult model."""
    
    def setUp(self):
        """Set up test data."""
        self.finding = Finding(
            type="buffer_overflow",
            severity=Severity.HIGH,
            file="test.c",
            line=10,
            column=5,
            message="Potential buffer overflow detected",
            recommendation="Use safer string functions"
        )
        
        self.result = AnalysisResult(
            analyzer="security_analyzer",
            status=AnalysisStatus.SUCCESS,
            findings=[self.finding],
            metrics={"score": 85.5, "issues_found": 1}
        )
    
    def test_valid_result(self):
        """Test creating a valid analysis result."""
        errors = self.result.validate()
        self.assertEqual(len(errors), 0)
    
    def test_empty_analyzer_name(self):
        """Test validation with empty analyzer name."""
        self.result.analyzer = ""
        errors = self.result.validate()
        self.assertIn("Analyzer name cannot be empty", errors)
    
    def test_invalid_finding(self):
        """Test validation with invalid finding."""
        self.finding.line = -1
        errors = self.result.validate()
        self.assertIn("Finding 1: line number must be non-negative", errors)
    
    def test_json_serialization(self):
        """Test JSON serialization and deserialization."""
        json_str = self.result.to_json()
        restored = AnalysisResult.from_json(json_str)
        
        self.assertEqual(self.result.analyzer, restored.analyzer)
        self.assertEqual(self.result.status, restored.status)
        self.assertEqual(len(self.result.findings), len(restored.findings))


class TestEvaluationReport(unittest.TestCase):
    """Test cases for EvaluationReport model."""
    
    def setUp(self):
        """Set up test data."""
        self.dimension_scores = DimensionScores(
            correctness=85.0,
            security=90.0,
            code_quality=75.0,
            performance=80.0,
            advanced_features=70.0
        )
        
        self.summary = EvaluationSummary(
            total_issues=5,
            critical_issues=1,
            compilation_status=True
        )
        
        self.report = EvaluationReport(
            evaluation_id="test-123",
            overall_score=82.5,
            grade=Grade.B,
            dimension_scores=self.dimension_scores,
            summary=self.summary,
            recommendations=["Use safer string functions", "Add error handling"]
        )
    
    def test_valid_report(self):
        """Test creating a valid evaluation report."""
        errors = self.report.validate()
        self.assertEqual(len(errors), 0)
    
    def test_invalid_overall_score(self):
        """Test validation with invalid overall score."""
        self.report.overall_score = 150.0
        errors = self.report.validate()
        self.assertIn("Overall score must be between 0.0 and 100.0", errors)
    
    def test_invalid_dimension_scores(self):
        """Test validation with invalid dimension scores."""
        self.dimension_scores.correctness_analyzer = -10.0
        errors = self.report.validate()
        self.assertIn("Dimension scores: correctness score must be between 0.0 and 100.0", errors)
    
    def test_json_serialization(self):
        """Test JSON serialization and deserialization."""
        json_str = self.report.to_json()
        restored = EvaluationReport.from_json(json_str)
        
        self.assertEqual(self.report.evaluation_id, restored.evaluation_id)
        self.assertEqual(self.report.overall_score, restored.overall_score)
        self.assertEqual(self.report.grade, restored.grade)


class TestEnums(unittest.TestCase):
    """Test cases for enum classes."""
    
    def test_analysis_depth_enum(self):
        """Test AnalysisDepth enum values."""
        self.assertEqual(AnalysisDepth.BASIC.value, "basic")
        self.assertEqual(AnalysisDepth.STANDARD.value, "standard")
        self.assertEqual(AnalysisDepth.COMPREHENSIVE.value, "comprehensive")
    
    def test_severity_enum(self):
        """Test Severity enum values."""
        self.assertEqual(Severity.CRITICAL.value, "critical")
        self.assertEqual(Severity.HIGH.value, "high")
        self.assertEqual(Severity.MEDIUM.value, "medium")
        self.assertEqual(Severity.LOW.value, "low")
        self.assertEqual(Severity.INFO.value, "info")
    
    def test_grade_enum(self):
        """Test Grade enum values."""
        self.assertEqual(Grade.A.value, "A")
        self.assertEqual(Grade.B.value, "B")
        self.assertEqual(Grade.C.value, "C")
        self.assertEqual(Grade.D.value, "D")
        self.assertEqual(Grade.F.value, "F")


if __name__ == '__main__':
    unittest.main()