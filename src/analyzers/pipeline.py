"""
Static Analysis Pipeline Orchestrator

This module implements the pipeline orchestrator that manages the execution
of multiple static analysis tools and coordinates result aggregation.
"""

import logging
from typing import Dict, List, Any, Optional, Type
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from dataclasses import dataclass

from ..core.interfaces import (
    BaseAnalyzer, AnalysisResult, AnalysisStatus, 
    ResultAggregator, Finding, Severity
)


@dataclass
class PipelineConfig:
    """Configuration for the analysis pipeline."""
    max_workers: int = 4
    timeout_seconds: int = 300
    fail_fast: bool = False
    enable_parallel: bool = True


class AnalyzerRegistry:
    """Registry for managing available analyzers."""
    
    def __init__(self):
        self._analyzers: Dict[str, Type[BaseAnalyzer]] = {}
        self._instances: Dict[str, BaseAnalyzer] = {}
    
    def register(self, analyzer_class: Type[BaseAnalyzer]) -> None:
        """Register an analyzer class."""
        # Create temporary instance to get name
        temp_instance = analyzer_class()
        self._analyzers[temp_instance.name] = analyzer_class
        logging.info(f"Registered analyzer: {temp_instance.name}")
    
    def get_analyzer(self, name: str) -> Optional[BaseAnalyzer]:
        """Get an analyzer instance by name."""
        if name not in self._instances:
            if name in self._analyzers:
                self._instances[name] = self._analyzers[name]()
            else:
                return None
        return self._instances[name]
    
    def list_analyzers(self) -> List[str]:
        """List all registered analyzer names."""
        return list(self._analyzers.keys())
    
    def clear(self) -> None:
        """Clear all registered analyzers."""
        self._analyzers.clear()
        self._instances.clear()


class StaticAnalysisPipeline:
    """
    Orchestrates the execution of multiple static analysis tools.
    
    This class manages the execution of registered analyzers, handles
    parallel execution, and coordinates result collection.
    """
    
    def __init__(self, config: Optional[PipelineConfig] = None):
        self.config = config or PipelineConfig()
        self.registry = AnalyzerRegistry()
        self.logger = logging.getLogger(__name__)
        
    def register_analyzer(self, analyzer_class: Type[BaseAnalyzer]) -> None:
        """Register an analyzer with the pipeline."""
        self.registry.register(analyzer_class)
    
    def run_analysis(
        self, 
        source_files: List[str], 
        analyzer_configs: Dict[str, Dict[str, Any]],
        selected_analyzers: Optional[List[str]] = None
    ) -> List[AnalysisResult]:
        """
        Run analysis pipeline on the provided source files.
        
        Args:
            source_files: List of source file paths to analyze
            analyzer_configs: Configuration for each analyzer
            selected_analyzers: Optional list of analyzer names to run
            
        Returns:
            List of analysis results from all analyzers
        """
        if not source_files:
            raise ValueError("No source files provided for analysis")
        
        # Determine which analyzers to run
        analyzers_to_run = selected_analyzers or self.registry.list_analyzers()
        
        if not analyzers_to_run:
            self.logger.warning("No analyzers available to run")
            return []
        
        self.logger.info(f"Starting analysis pipeline with {len(analyzers_to_run)} analyzers")
        self.logger.info(f"Analyzing {len(source_files)} source files")
        
        results = []
        
        if self.config.enable_parallel and len(analyzers_to_run) > 1:
            results = self._run_parallel_analysis(
                source_files, analyzer_configs, analyzers_to_run
            )
        else:
            results = self._run_sequential_analysis(
                source_files, analyzer_configs, analyzers_to_run
            )
        
        self.logger.info(f"Analysis pipeline completed with {len(results)} results")
        return results
    
    def _run_parallel_analysis(
        self,
        source_files: List[str],
        analyzer_configs: Dict[str, Dict[str, Any]],
        analyzer_names: List[str]
    ) -> List[AnalysisResult]:
        """Run analyzers in parallel using ThreadPoolExecutor."""
        results = []
        
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            # Submit all analyzer tasks
            future_to_analyzer = {}
            for analyzer_name in analyzer_names:
                analyzer = self.registry.get_analyzer(analyzer_name)
                if analyzer is None:
                    self.logger.error(f"Analyzer '{analyzer_name}' not found")
                    continue
                
                config = analyzer_configs.get(analyzer_name, {})
                future = executor.submit(
                    self._run_single_analyzer,
                    analyzer, source_files, config
                )
                future_to_analyzer[future] = analyzer_name
            
            # Collect results as they complete
            for future in as_completed(future_to_analyzer, timeout=self.config.timeout_seconds):
                analyzer_name = future_to_analyzer[future]
                try:
                    result = future.result()
                    results.append(result)
                    self.logger.info(f"Completed analysis: {analyzer_name}")
                except Exception as e:
                    self.logger.error(f"Analyzer '{analyzer_name}' failed: {str(e)}")
                    if self.config.fail_fast:
                        # Cancel remaining tasks
                        for remaining_future in future_to_analyzer:
                            remaining_future.cancel()
                        raise
                    
                    # Create failure result
                    failure_result = AnalysisResult(
                        analyzer=analyzer_name,
                        status=AnalysisStatus.FAILURE,
                        findings=[],
                        metrics={"error": str(e)},
                        score=0.0
                    )
                    results.append(failure_result)
        
        return results
    
    def _run_sequential_analysis(
        self,
        source_files: List[str],
        analyzer_configs: Dict[str, Dict[str, Any]],
        analyzer_names: List[str]
    ) -> List[AnalysisResult]:
        """Run analyzers sequentially."""
        results = []
        
        for analyzer_name in analyzer_names:
            analyzer = self.registry.get_analyzer(analyzer_name)
            if analyzer is None:
                self.logger.error(f"Analyzer '{analyzer_name}' not found")
                continue
            
            config = analyzer_configs.get(analyzer_name, {})
            
            try:
                result = self._run_single_analyzer(analyzer, source_files, config)
                results.append(result)
                self.logger.info(f"Completed analysis: {analyzer_name}")
            except Exception as e:
                self.logger.error(f"Analyzer '{analyzer_name}' failed: {str(e)}")
                if self.config.fail_fast:
                    raise
                
                # Create failure result
                failure_result = AnalysisResult(
                    analyzer=analyzer_name,
                    status=AnalysisStatus.FAILURE,
                    findings=[],
                    metrics={"error": str(e)},
                    score=0.0
                )
                results.append(failure_result)
        
        return results
    
    def _run_single_analyzer(
        self,
        analyzer: BaseAnalyzer,
        source_files: List[str],
        config: Dict[str, Any]
    ) -> AnalysisResult:
        """Run a single analyzer with error handling and timing."""
        start_time = time.time()
        
        try:
            # Validate configuration
            if not analyzer.validate_config(config):
                raise ValueError(f"Invalid configuration for analyzer {analyzer.name}")
            
            # Run the analysis
            result = analyzer.analyze(source_files, config)
            
            # Add timing information
            execution_time = time.time() - start_time
            result.metrics["execution_time"] = execution_time
            
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Analyzer {analyzer.name} failed after {execution_time:.2f}s: {str(e)}")
            raise
    
    def get_analyzer_info(self) -> Dict[str, Dict[str, str]]:
        """Get information about all registered analyzers."""
        info = {}
        for name in self.registry.list_analyzers():
            analyzer = self.registry.get_analyzer(name)
            if analyzer:
                info[name] = {
                    "name": analyzer.name,
                    "version": analyzer.version
                }
        return info