"""
Tests for the static analysis pipeline and result aggregation.
"""

import unittest
from unittest.mock import Mock, patch
from typing import Dict, List, Any

from src.core.interfaces import BaseAnalyzer, AnalysisResult, AnalysisStatus, Finding, Severity
from src.analyzers.pipeline import StaticAnalysisPipeline, AnalyzerRegistry, PipelineConfig
from src.analyzers.aggregator import StandardResultAggregator, AggregationConfig


class MockAnalyzer(BaseAnalyzer):
    """Mock analyzer for testing."""
    
    def __init__(self, name: str = "mock_analyzer", version: str = "1.0.0"):
        self._name = name
        self._version = version
    
    @property
    def name(self) -> str:
        return self._name
    
    @property
    def version(self) -> str:
        return self._version
    
    def analyze(self, source_files: List[str], config: Dict[str, Any]) -> AnalysisResult:
        # Create mock findings
        findings = [
            Finding(
                type="test_issue",
                severity=Severity.MEDIUM,
                file=source_files[0] if source_files else "test.c",
                line=10,
                column=5,
                message="Test finding",
                recommendation="Fix the test issue"
            )
        ]
        
        return AnalysisResult(
            analyzer=self.name,
            status=AnalysisStatus.SUCCESS,
            findings=findings,
            metrics={"test_metric": 42},
            score=85.0
        )
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        return True


class TestAnalyzerRegistry(unittest.TestCase):
    """Test cases for AnalyzerRegistry."""
    
    def setUp(self):
        self.registry = AnalyzerRegistry()
    
    def test_register_analyzer(self):
        """Test registering an analyzer."""
        self.registry.register(MockAnalyzer)
        analyzers = self.registry.list_analyzers()
        self.assertIn("mock_analyzer", analyzers)
    
    def test_get_analyzer(self):
        """Test getting an analyzer instance."""
        self.registry.register(MockAnalyzer)
        analyzer = self.registry.get_analyzer("mock_analyzer")
        self.assertIsNotNone(analyzer)
        self.assertEqual(analyzer.name, "mock_analyzer")
    
    def test_get_nonexistent_analyzer(self):
        """Test getting a non-existent analyzer."""
        analyzer = self.registry.get_analyzer("nonexistent")
        self.assertIsNone(analyzer)
    
    def test_clear_registry(self):
        """Test clearing the registry."""
        self.registry.register(MockAnalyzer)
        self.registry.clear()
        analyzers = self.registry.list_analyzers()
        self.assertEqual(len(analyzers), 0)


class TestStaticAnalysisPipeline(unittest.TestCase):
    """Test cases for StaticAnalysisPipeline."""
    
    def setUp(self):
        self.pipeline = StaticAnalysisPipeline()
        self.pipeline.register_analyzer(MockAnalyzer)
    
    def test_register_analyzer(self):
        """Test registering an analyzer with the pipeline."""
        class AnotherMockAnalyzer(MockAnalyzer):
            def __init__(self):
                super().__init__("another_mock", "2.0.0")
        
        self.pipeline.register_analyzer(AnotherMockAnalyzer)
        info = self.pipeline.get_analyzer_info()
        self.assertIn("another_mock", info)
    
    def test_run_analysis_sequential(self):
        """Test running analysis in sequential mode."""
        config = PipelineConfig(enable_parallel=False)
        pipeline = StaticAnalysisPipeline(config)
        pipeline.register_analyzer(MockAnalyzer)
        
        source_files = ["test.c"]
        analyzer_configs = {"mock_analyzer": {}}
        
        results = pipeline.run_analysis(source_files, analyzer_configs)
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].analyzer, "mock_analyzer")
        self.assertEqual(results[0].status, AnalysisStatus.SUCCESS)
    
    def test_run_analysis_parallel(self):
        """Test running analysis in parallel mode."""
        config = PipelineConfig(enable_parallel=True, max_workers=2)
        pipeline = StaticAnalysisPipeline(config)
        pipeline.register_analyzer(MockAnalyzer)
        
        source_files = ["test.c"]
        analyzer_configs = {"mock_analyzer": {}}
        
        results = pipeline.run_analysis(source_files, analyzer_configs)
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].analyzer, "mock_analyzer")
        self.assertEqual(results[0].status, AnalysisStatus.SUCCESS)
    
    def test_run_analysis_no_source_files(self):
        """Test running analysis with no source files."""
        with self.assertRaises(ValueError):
            self.pipeline.run_analysis([], {})
    
    def test_run_analysis_selected_analyzers(self):
        """Test running analysis with selected analyzers."""
        # Register multiple analyzers
        class SecondMockAnalyzer(MockAnalyzer):
            def __init__(self):
                super().__init__("second_mock", "1.0.0")
        
        self.pipeline.register_analyzer(SecondMockAnalyzer)
        
        source_files = ["test.c"]
        analyzer_configs = {"mock_analyzer": {}, "second_mock": {}}
        selected_analyzers = ["mock_analyzer"]
        
        results = self.pipeline.run_analysis(
            source_files, analyzer_configs, selected_analyzers
        )
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].analyzer, "mock_analyzer")


class TestStandardResultAggregator(unittest.TestCase):
    """Test cases for StandardResultAggregator."""
    
    def setUp(self):
        self.aggregator = StandardResultAggregator()
    
    def test_aggregate_empty_results(self):
        """Test aggregating empty results."""
        aggregation = self.aggregator.aggregate([])
        self.assertEqual(aggregation["total_analyzers"], 0)
        self.assertEqual(aggregation["total_findings"], 0)
    
    def test_aggregate_single_result(self):
        """Test aggregating a single result."""
        finding = Finding(
            type="test_issue",
            severity=Severity.HIGH,
            file="test.c",
            line=10,
            column=5,
            message="Test finding",
            recommendation="Fix it"
        )
        
        result = AnalysisResult(
            analyzer="test_analyzer",
            status=AnalysisStatus.SUCCESS,
            findings=[finding],
            metrics={"score": 80.0},
            score=80.0
        )
        
        aggregation = self.aggregator.aggregate([result])
        
        self.assertEqual(aggregation["total_analyzers"], 1)
        self.assertEqual(aggregation["successful_analyzers"], 1)
        self.assertEqual(aggregation["total_findings"], 1)
        self.assertEqual(len(aggregation["findings"]), 1)
    
    def test_resolve_conflicts_no_duplicates(self):
        """Test conflict resolution with no duplicates."""
        finding1 = Finding(
            type="issue1", severity=Severity.HIGH, file="test.c",
            line=10, column=5, message="Issue 1", recommendation="Fix 1"
        )
        finding2 = Finding(
            type="issue2", severity=Severity.MEDIUM, file="test.c",
            line=20, column=10, message="Issue 2", recommendation="Fix 2"
        )
        
        result1 = AnalysisResult(
            analyzer="analyzer1", status=AnalysisStatus.SUCCESS,
            findings=[finding1], metrics={}, score=80.0
        )
        result2 = AnalysisResult(
            analyzer="analyzer2", status=AnalysisStatus.SUCCESS,
            findings=[finding2], metrics={}, score=75.0
        )
        
        deduplicated = self.aggregator.resolve_conflicts([result1, result2])
        self.assertEqual(len(deduplicated), 2)
    
    def test_resolve_conflicts_with_duplicates(self):
        """Test conflict resolution with duplicate findings."""
        # Same location, different analyzers
        finding1 = Finding(
            type="issue1", severity=Severity.HIGH, file="test.c",
            line=10, column=5, message="Issue from analyzer 1", recommendation="Fix 1"
        )
        finding2 = Finding(
            type="issue1", severity=Severity.MEDIUM, file="test.c",
            line=10, column=5, message="Issue from analyzer 2", recommendation="Fix 2"
        )
        
        result1 = AnalysisResult(
            analyzer="analyzer1", status=AnalysisStatus.SUCCESS,
            findings=[finding1], metrics={}, score=80.0
        )
        result2 = AnalysisResult(
            analyzer="analyzer2", status=AnalysisStatus.SUCCESS,
            findings=[finding2], metrics={}, score=75.0
        )
        
        deduplicated = self.aggregator.resolve_conflicts([result1, result2])
        
        # Should have only one finding (the one with higher severity)
        self.assertEqual(len(deduplicated), 1)
        self.assertEqual(deduplicated[0].severity, Severity.HIGH)
        self.assertIn("analyzer1", deduplicated[0].message)


if __name__ == "__main__":
    unittest.main()