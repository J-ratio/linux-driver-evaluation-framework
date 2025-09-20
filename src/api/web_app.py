"""FastAPI web application for Linux Driver Evaluation Framework."""

import os
import uuid
import asyncio
from typing import List, Optional
from pathlib import Path

from fastapi import FastAPI, File, UploadFile, HTTPException, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from src.models.evaluation import EvaluationRequest, EvaluationReport, SourceFile
from .pipeline import AnalysisPipeline
from src.services.validation import ValidationService
import warnings

warnings.filterwarnings('ignore', category=UserWarning, message="Pydantic serializer warnings.*")

class EvaluationStatus(BaseModel):
    """Model for evaluation status tracking."""
    id: str
    status: str  # "pending", "running", "completed", "failed"
    progress: int  # 0-100
    message: str
    result: Optional[EvaluationReport] = None


# Global storage for evaluation status (in production, use Redis or database)
evaluation_status: dict[str, EvaluationStatus] = {}

app = FastAPI(
    title="Linux Driver Evaluation Framework",
    description="Web interface for evaluating Linux device driver code quality",
    version="1.0.0"
)

# Mount static files and templates
static_path = Path(__file__).parent.parent.parent / "static"
templates_path = Path(__file__).parent.parent.parent / "templates"

if static_path.exists():
    app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

templates = Jinja2Templates(directory=str(templates_path))


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Serve the main code submission interface."""
    import time
    return templates.TemplateResponse("index.html", {
        "request": request,
        "timestamp": int(time.time())
    })


@app.get("/results", response_class=HTMLResponse)
async def results_page(request: Request):
    """Serve the results browsing interface."""
    import time
    return templates.TemplateResponse("results.html", {
        "request": request, 
        "timestamp": int(time.time())
    })


@app.post("/api/submit")
async def submit_code(
    background_tasks: BackgroundTasks,
    files: List[UploadFile] = File(...)
):
    """Submit driver code files for evaluation."""
    if not files:
        raise HTTPException(status_code=400, detail="No files provided")
    
    # Validate files
    validation_service = ValidationService()
    source_files = []
    
    for file in files:
        if not file.filename or not file.filename.endswith('.c'):
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid file type: {file.filename}. Only .c files are accepted."
            )
        
        content = await file.read()
        try:
            content_str = content.decode('utf-8')
        except UnicodeDecodeError:
            raise HTTPException(
                status_code=400,
                detail=f"File {file.filename} is not valid UTF-8 text"
            )
        
        # Basic validation
        if not validation_service.is_valid_driver_code(content_str):
            raise HTTPException(
                status_code=400,
                detail=f"File {file.filename} does not appear to contain Linux driver code"
            )
        
        source_files.append(SourceFile(
            filename=file.filename,
            content=content_str,
            size=len(content)
        ))
    
    # Create evaluation request
    evaluation_id = str(uuid.uuid4())
    evaluation_request = EvaluationRequest(
        id=evaluation_id,
        source_files=source_files
    )
    
    # Initialize status tracking
    evaluation_status[evaluation_id] = EvaluationStatus(
        id=evaluation_id,
        status="pending",
        progress=0,
        message="Evaluation queued"
    )
    
    # Start background evaluation
    background_tasks.add_task(run_evaluation, evaluation_request)
    
    return {"evaluation_id": evaluation_id, "status": "submitted"}


@app.get("/api/status/{evaluation_id}")
async def get_evaluation_status(evaluation_id: str):
    """Get the status of an evaluation."""
    if evaluation_id not in evaluation_status:
        raise HTTPException(status_code=404, detail="Evaluation not found")
    
    return evaluation_status[evaluation_id]


@app.get("/api/results/{evaluation_id}")
async def get_evaluation_results(evaluation_id: str):
    """Get the results of a completed evaluation."""
    if evaluation_id not in evaluation_status:
        raise HTTPException(status_code=404, detail="Evaluation not found")
    
    status = evaluation_status[evaluation_id]
    if status.status != "completed":
        raise HTTPException(status_code=400, detail="Evaluation not completed")
    
    return status.result


@app.get("/api/evaluations")
async def list_evaluations():
    """List all evaluations with their status."""
    return list(evaluation_status.values())


@app.get("/api/sample-drivers")
async def get_sample_drivers():
    """Get available sample drivers."""
    sample_drivers = {
        "simple_hello": {
            "name": "Simple Hello Driver",
            "description": "A minimal kernel module that demonstrates basic module loading/unloading",
            "filename": "simple_hello_driver.c",
            "complexity": "Beginner",
            "expected_grade": "B+"
        },
        "character_device": {
            "name": "Character Device Driver", 
            "description": "A full-featured character device driver with proper error handling",
            "filename": "demo_driver.c",
            "complexity": "Intermediate",
            "expected_grade": "A-"
        },
        "network_device": {
            "name": "Network Device Driver",
            "description": "A network interface driver demonstrating packet handling",
            "filename": "network_driver_sample.c", 
            "complexity": "Advanced",
            "expected_grade": "B"
        },
        "problematic": {
            "name": "Problematic Driver",
            "description": "Contains intentional security vulnerabilities and coding issues",
            "filename": "problematic_driver.c",
            "complexity": "Educational",
            "expected_grade": "D"
        }
    }
    return sample_drivers


@app.get("/api/sample-drivers/{driver_name}")
async def get_sample_driver_content(driver_name: str):
    """Get the content of a specific sample driver."""
    driver_files = {
        "simple_hello": "examples/simple_hello_driver.c",
        "character_device": "examples/demo_driver.c", 
        "network_device": "examples/network_driver_sample.c",
        "problematic": "examples/problematic_driver.c"
    }
    
    if driver_name not in driver_files:
        raise HTTPException(status_code=404, detail="Sample driver not found")
    
    file_path = Path(__file__).parent.parent.parent / driver_files[driver_name]
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Sample driver file not found")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return {
            "filename": file_path.name,
            "content": content,
            "size": len(content)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading sample driver: {str(e)}")


@app.get("/api/analyzer-status")
async def get_analyzer_status():
    """Get the status of all analyzers."""
    try:
        from .pipeline import AnalysisPipeline
        pipeline = AnalysisPipeline()
        status = pipeline.get_analyzer_status()
        return {
            "status": "ok",
            "analyzers": status,
            "pipeline_type": "real"
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "pipeline_type": "fallback"
        }


async def run_evaluation(evaluation_request: EvaluationRequest):
    """Run the evaluation pipeline in the background."""
    evaluation_id = evaluation_request.id
    
    try:
        # Update status to running
        evaluation_status[evaluation_id].status = "running"
        evaluation_status[evaluation_id].message = "Starting analysis..."
        evaluation_status[evaluation_id].progress = 10
        
        # Use real analysis pipeline - NO FALLBACKS
        pipeline = AnalysisPipeline()
        
        # Define progress callback
        def update_progress(progress: int, message: str):
            evaluation_status[evaluation_id].progress = progress
            evaluation_status[evaluation_id].message = message
        
        # Execute the real analysis pipeline with progress tracking
        result = await pipeline.evaluate_async(evaluation_request, update_progress)
        
        # Update status to completed
        evaluation_status[evaluation_id].status = "completed"
        evaluation_status[evaluation_id].progress = 100
        evaluation_status[evaluation_id].message = "Evaluation completed"
        evaluation_status[evaluation_id].result = result
        
    except Exception as e:
        # Update status to failed
        evaluation_status[evaluation_id].status = "failed"
        evaluation_status[evaluation_id].message = f"Evaluation failed: {str(e)}"
        evaluation_status[evaluation_id].progress = 0


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)