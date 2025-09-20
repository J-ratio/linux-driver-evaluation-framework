"""
Unit tests for the scoring and grading system.

Tests the weighted scoring algorithm, normalization functions, and grade
classification logic to ensure accurate evaluation results.
"""

import unittest
from unittest.mock import Mock, patch
from src.analyzers.scoring import WeightedScoringSystem, ScoringWeights
from src.analyzers.aggregator import EvaluationResultsAggregator, ConflictResolutionRule
from src.models.evaluation import (
    AnalysisResult, Finding, Severity, AnalysisStatus, Grade, DimensionScores
)


class TestScoringWeights(unittest.TestCase):
    """Test scoring weights validation."""
    
    def test_default_weights_sum_to_one(self):
        """Test that default weights sum to 1.0."""
        weights = ScoringWeights()
        self.assertTrue(weights.validate())
    
    def test_custom_weights_validation(self):
        """Test validation of custom weights."""
        # Valid weights
        valid_weights = ScoringWeights(
            correctness=0.5, security=0.2, code_quality=0.2, 
            performance=0.05, advanced_features=0.05
        )
        self.assertTrue(valid_weights.validate())
        
        # Invalid weights (don't sum to 1.0)
        invalid_weights = ScoringWeights(
            correctness=0.5, security=0.5, code_quality=0.2, 
            performance=0.1, advanced_features=0.1
        )
        self.assertFalse(invalid_weights.validate())


class TestWeightedScoringSystem(unittest.TestCase):
    """Test the weighted scoring system."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.scoring_system = WeightedScoringSystem()
    
    def test_initialization_with_invalid_weights(self):
        """Test that initialization fails with invalid weights."""
        invalid_weights = ScoringWeights(
            correctness=0.5, security=0.5, code_quality=0.5, 
            performance=0.5, advanced_features=0.5
        )
        with self.assertRaises(ValueError):
            WeightedScoringSystem(invalid_weights)
    
    def test_normalize_score(self):
        """Test score normalization."""
        # Normal case
        self.assertEqual(self.scoring_system.normalize_score(50, 100), 50.0)
        
        # Score exceeds maximum
        self.assertEqual(self.scoring_system.normalize_score(150, 100), 100.0)
        
        # Negative score
        self.assertEqual(self.scoring_system.normalize_score(-10, 100), 0.0)
        
        # Zero maximum
        self.assertEqual(self.scoring_system.normalize_score(50, 0), 0.0)
    
    def test_calculate_severity_penalty(self):
        """Test severity penalty calculation."""
        findings = [
            Finding("error", Severity.CRITICAL, "test.c", 10, 5, "Critical error", ""),
            Finding("warning", Severity.HIGH, "test.c", 20, 5, "High warning", ""),
            Finding("info", Severity.INFO, "test.c", 30, 5, "Info message", "")
        ]
        
        penalty = self.scoring_system.calculate_severity_penalty(findings)
        expected = 20.0 + 10.0 + 0.5  # Critical + High + Info
        self.assertEqual(penalty, expected)
        
        # Empty findings
        self.assertEqual(self.scoring_system.calculate_severity_penalty([]), 0.0)
    
    def test_assign_grade(self):
        """Test grade assignment based on scores."""
        self.assertEqual(self.scoring_system.assign_grade(95.0), Grade.A)
        self.assertEqual(self.scoring_system.assign_grade(85.0), Grade.B)
        self.assertEqual(self.scoring_system.assign_grade(75.0), Grade.C)
        self.assertEqual(self.scoring_system.assign_grade(65.0), Grade.D)
        self.assertEqual(self.scoring_system.assign_grade(55.0), Grade.F)
        
        # Boundary cases
        self.assertEqual(self.scoring_system.assign_grade(90.0), Grade.A)
        self.assertEqual(self.scoring_system.assign_grade(89.9), Grade.B)
    
    def test_calculate_dimension_score(self):
        """Test dimension score calculation."""
        # Create mock analysis results
        correctness_result = AnalysisResult(
            analyzer="correctness",
            status=AnalysisStatus.SUCCESS,
            findings=[
                Finding("error", Severity.MEDIUM, "test.c", 10, 5, "Medium error", "")
            ],
            metrics={"score": 85.0}
        )
        
        score = self.scoring_system.calculate_dimension_score([correctness_result], "correctness")
        
        # Score should be 100 - penalty for medium finding (5.0)
        expected_score = 100.0 - 5.0
        self.assertEqual(score, expected_score)
    
    def test_get_dimension_scores(self):
        """Test getting scores for all dimensions."""
        # Create mock results for different analyzers
        results = [
            AnalysisResult("correctness", AnalysisStatus.SUCCESS, [], {}),
            AnalysisResult("security", AnalysisStatus.SUCCESS, [], {}),
            AnalysisResult("code_quality", AnalysisStatus.SUCCESS, [], {}),
            AnalysisResult("performance", AnalysisStatus.SUCCESS, [], {}),
            AnalysisResult("advanced_features", AnalysisStatus.SUCCESS, [], {})
        ]
        
        dimension_scores = self.scoring_system.get_dimension_scores(results)
        
        self.assertIsInstance(dimension_scores, DimensionScores)
        self.assertEqual(dimension_scores.correctness, 100.0)  # No findings = perfect score
        self.assertEqual(dimension_scores.security, 100.0)
        self.assertEqual(dimension_scores.code_quality, 100.0)
        self.assertEqual(dimension_scores.performance, 100.0)
        self.assertEqual(dimension_scores.advanced_features, 100.0)
    
    def test_calculate_overall_score(self):
        """Test overall score calculation with weighted average."""
        # Create results with perfect scores
        results = [
            AnalysisResult("correctness", AnalysisStatus.SUCCESS, [], {}),
            AnalysisResult("security", AnalysisStatus.SUCCESS, [], {}),
            AnalysisResult("code_quality", AnalysisStatus.SUCCESS, [], {}),
            AnalysisResult("performance", AnalysisStatus.SUCCESS, [], {}),
            AnalysisResult("advanced_features", AnalysisStatus.SUCCESS, [], {})
        ]
        
        overall_score = self.scoring_system.calculate_score(results)
        self.assertEqual(overall_score, 100.0)
    
    def test_generate_recommendations(self):
        """Test recommendation generation."""
        results = [
            AnalysisResult(
                "security",
                AnalysisStatus.SUCCESS,
                [Finding("vuln", Severity.CRITICAL, "test.c", 10, 5, "Critical vulnerability", "")],
                {}
            ),
            AnalysisResult(
                "code_quality",
                AnalysisStatus.SUCCESS,
                [Finding("style", Severity.MEDIUM, "test.c", i, 5, f"Style issue {i}", "") 
                 for i in range(15)],  # Many medium issues
                {}
            )
        ]
        
        recommendations = self.scoring_system.generate_recommendations(results)
        
        self.assertGreater(len(recommendations), 0)
        # Should have recommendations for critical issues and many medium issues
        critical_rec = any("critical" in rec.lower() for rec in recommendations)
        style_rec = any("style" in rec.lower() or "quality" in rec.lower() for rec in recommendations)
        
        self.assertTrue(critical_rec)
        self.assertTrue(style_rec)


class TestEvaluationResultsAggregator(unittest.TestCase):
    """Test the results aggregation engine."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.aggregator = EvaluationResultsAggregator()
    
    def test_empty_results_aggregation(self):
        """Test aggregation with empty results list."""
        aggregated = self.aggregator.aggregate([])
        
        self.assertEqual(aggregated["total_findings"], 0)
        self.assertEqual(aggregated["overall_score"], 0.0)
        self.assertEqual(aggregated["grade"], Grade.F.value)
        self.assertTrue(aggregated["compilation_success"])
    
    def test_conflict_resolution_similar_findings(self):
        """Test conflict resolution for similar findings."""
        # Create similar findings from different analyzers
        finding1 = Finding("error", Severity.HIGH, "test.c", 10, 5, "Buffer overflow detected", "")
        finding2 = Finding("error", Severity.CRITICAL, "test.c", 11, 5, "Buffer overflow found", "")
        
        results = [
            AnalysisResult("security", AnalysisStatus.SUCCESS, [finding1], {}),
            AnalysisResult("correctness", AnalysisStatus.SUCCESS, [finding2], {})
        ]
        
        resolved = self.aggregator.resolve_conflicts(results)
        
        # Should merge similar findings
        self.assertEqual(len(resolved), 1)
        # Should use higher severity
        self.assertEqual(resolved[0].severity, Severity.CRITICAL)
    
    def test_conflict_resolution_different_findings(self):
        """Test that different findings are not merged."""
        finding1 = Finding("error", Severity.HIGH, "test.c", 10, 5, "Buffer overflow", "")
        finding2 = Finding("warning", Severity.MEDIUM, "other.c", 50, 10, "Unused variable", "")
        
        results = [
            AnalysisResult("security", AnalysisStatus.SUCCESS, [finding1], {}),
            AnalysisResult("code_quality", AnalysisStatus.SUCCESS, [finding2], {})
        ]
        
        resolved = self.aggregator.resolve_conflicts(results)
        
        # Should keep both findings
        self.assertEqual(len(resolved), 2)
    
    def test_message_similarity_calculation(self):
        """Test message similarity calculation."""
        # Similar messages
        similarity1 = self.aggregator._calculate_message_similarity(
            "Buffer overflow detected in function",
            "Buffer overflow found in function"
        )
        self.assertGreater(similarity1, 0.8)
        
        # Different messages
        similarity2 = self.aggregator._calculate_message_similarity(
            "Buffer overflow detected",
            "Unused variable warning"
        )
        self.assertLess(similarity2, 0.3)
        
        # Empty messages
        similarity3 = self.aggregator._calculate_message_similarity("", "")
        self.assertEqual(similarity3, 1.0)
    
    def test_comprehensive_report_creation(self):
        """Test creation of comprehensive evaluation report."""
        results = [
            AnalysisResult(
                "correctness",
                AnalysisStatus.SUCCESS,
                [Finding("error", Severity.HIGH, "test.c", 10, 5, "Logic error", "Fix logic")],
                {"complexity": 5}
            ),
            AnalysisResult(
                "security",
                AnalysisStatus.SUCCESS,
                [Finding("vuln", Severity.CRITICAL, "test.c", 20, 5, "Security issue", "Use safe function")],
                {"vulnerabilities": 1}
            )
        ]
        
        report = self.aggregator.create_comprehensive_report("test-eval-123", results)
        
        self.assertEqual(report.evaluation_id, "test-eval-123")
        self.assertIsInstance(report.overall_score, float)
        self.assertIsInstance(report.grade, Grade)
        self.assertIsInstance(report.dimension_scores, DimensionScores)
        self.assertGreater(len(report.detailed_findings), 0)
        self.assertGreater(len(report.recommendations), 0)
    
    def test_detailed_breakdown(self):
        """Test detailed breakdown generation."""
        results = [
            AnalysisResult("correctness", AnalysisStatus.SUCCESS, [], {}),
            AnalysisResult("security", AnalysisStatus.SUCCESS, [], {})
        ]
        
        breakdown = self.aggregator.get_detailed_breakdown(results)
        
        self.assertIn("overall_score", breakdown)
        self.assertIn("overall_grade", breakdown)
        self.assertIn("dimension_breakdown", breakdown)
        self.assertIn("analyzer_contributions", breakdown)
        self.assertIn("conflict_resolution_stats", breakdown)
        
        # Check dimension breakdown structure
        for dimension in ["correctness", "security", "code_quality", "performance", "advanced_features"]:
            if dimension in breakdown["dimension_breakdown"]:
                dim_data = breakdown["dimension_breakdown"][dimension]
                self.assertIn("score", dim_data)
                self.assertIn("weight", dim_data)
                self.assertIn("contribution_to_overall", dim_data)
                self.assertIn("grade", dim_data)


class TestConflictResolutionRule(unittest.TestCase):
    """Test conflict resolution rule configuration."""
    
    def test_default_priority_order(self):
        """Test default analyzer priority order."""
        rule = ConflictResolutionRule()
        
        expected_order = ["compilation", "security", "correctness", "code_quality", "performance"]
        self.assertEqual(rule.priority_order, expected_order)
        self.assertTrue(rule.merge_similar)
        self.assertEqual(rule.similarity_threshold, 0.8)
    
    def test_custom_configuration(self):
        """Test custom conflict resolution configuration."""
        rule = ConflictResolutionRule(
            priority_order=["security", "correctness"],
            merge_similar=False,
            similarity_threshold=0.9
        )
        
        self.assertEqual(rule.priority_order, ["security", "correctness"])
        self.assertFalse(rule.merge_similar)
        self.assertEqual(rule.similarity_threshold, 0.9)


if __name__ == '__main__':
    unittest.main()