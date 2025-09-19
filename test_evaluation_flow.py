#!/usr/bin/env python3
"""
Test the complete evaluation flow with actual file submission.
"""

import sys
import os
from pathlib import Path
import asyncio

# Add src directory to Python path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

async def test_evaluation_flow():
    """Test the complete evaluation flow."""
    try:
        from models.evaluation import EvaluationRequest, SourceFile
        from api.simple_pipeline import AnalysisPipeline
        
        # Create a test source file
        test_code = '''
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

static int __init hello_init(void) {
    printk(KERN_INFO "Hello, World!\\n");
    return 0;
}

static void __exit hello_exit(void) {
    printk(KERN_INFO "Goodbye, World!\\n");
}

module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");
'''
        
        # Create SourceFile object
        source_file = SourceFile(
            filename="test_driver.c",
            content=test_code,
            size=len(test_code)
        )
        
        # Create evaluation request
        evaluation_request = EvaluationRequest(
            id="test-evaluation-123",
            source_files=[source_file]
        )
        
        print("✓ Created evaluation request successfully")
        
        # Test the pipeline
        pipeline = AnalysisPipeline()
        result = await pipeline.evaluate_async(evaluation_request)
        
        print("✓ Pipeline evaluation completed successfully")
        print(f"  - Evaluation ID: {result.evaluation_id}")
        print(f"  - Overall Score: {result.overall_score:.1f}")
        print(f"  - Grade: {result.grade.value}")
        print(f"  - Total Issues: {result.summary.total_issues}")
        print(f"  - Critical Issues: {result.summary.critical_issues}")
        print(f"  - Compilation Status: {'Success' if result.summary.compilation_status else 'Failed'}")
        
        return True
        
    except Exception as e:
        print(f"✗ Evaluation flow test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run the evaluation flow test."""
    print("Testing Complete Evaluation Flow...")
    print("=" * 50)
    
    # Run the async test
    success = asyncio.run(test_evaluation_flow())
    
    print("=" * 50)
    if success:
        print("🎉 Evaluation flow test passed!")
        print("\nThe web interface should now work correctly for file submissions.")
    else:
        print("❌ Evaluation flow test failed!")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())