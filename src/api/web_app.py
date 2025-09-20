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
from src.config.manager import DefaultConfigurationManager
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
    files: List[UploadFile] = File(...),
    kernel_version: Optional[str] = None,
    target_architecture: Optional[str] = None
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
    
    # Handle kernel version and architecture selection
    config_manager = DefaultConfigurationManager()
    config = config_manager.load_config()
    
    if kernel_version:
        # Validate the provided kernel version
        available_versions = config_manager.get_available_kernel_versions()
        if kernel_version not in available_versions:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported kernel version '{kernel_version}'. Available: {available_versions}"
            )
        selected_kernel_version = kernel_version
    else:
        # Use default kernel version from config
        selected_kernel_version = config.get("compilation", {}).get("kernel_version", "5.15")
    
    if target_architecture:
        # Validate the provided architecture
        available_architectures = config.get("compilation", {}).get("available_architectures", ["x86_64"])
        if target_architecture not in available_architectures:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported architecture '{target_architecture}'. Available: {available_architectures}"
            )
        selected_architecture = target_architecture
    else:
        # Use default architecture from config
        selected_architecture = config.get("compilation", {}).get("target_architecture", "x86_64")
    
    # Create evaluation configuration
    from src.models.evaluation import EvaluationConfiguration
    eval_config = EvaluationConfiguration(
        kernel_version=selected_kernel_version,
        target_architecture=selected_architecture
    )
    
    evaluation_request = EvaluationRequest(
        id=evaluation_id,
        source_files=source_files,
        configuration=eval_config
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


@app.get("/api/kernel-versions")
async def get_kernel_versions():
    """Get available kernel versions."""
    try:
        config_manager = DefaultConfigurationManager()
        available_versions = config_manager.get_available_kernel_versions()
        current_version = config_manager.load_config().get("compilation", {}).get("kernel_version", "5.15")
        compilation_config = config_manager.load_config().get("compilation", {})
        version_configs = compilation_config.get("kernel_version_configs", {})
        
        versions_info = []
        for version in available_versions:
            config = version_configs.get(version, {})
            versions_info.append({
                "version": version,
                "description": config.get("description", f"Kernel {version}"),
                "docker_image": config.get("docker_image", "ubuntu:22.04"),
                "headers_package": config.get("headers_package", "linux-headers-generic"),
                "is_current": version == current_version
            })
        
        return {
            "status": "ok",
            "current_version": current_version,
            "available_versions": versions_info
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting kernel versions: {str(e)}")


@app.post("/api/kernel-versions/set")
async def set_kernel_version(request: dict):
    """Set the default kernel version."""
    try:
        version = request.get("version")
        if not version:
            raise HTTPException(status_code=400, detail="Version is required")
        
        config_manager = DefaultConfigurationManager()
        available_versions = config_manager.get_available_kernel_versions()
        
        if version not in available_versions:
            raise HTTPException(
                status_code=400, 
                detail=f"Unsupported kernel version '{version}'. Available: {available_versions}"
            )
        
        # Load and update config
        config = config_manager.load_config()
        config["compilation"]["kernel_version"] = version
        
        # Save config
        if not config_manager.save_config(config):
            raise HTTPException(status_code=500, detail="Failed to save configuration")
        
        # Get version info
        kernel_config = config_manager.get_kernel_version_config(version)
        
        return {
            "status": "ok",
            "message": f"Successfully set default kernel version to {version}",
            "version_info": {
                "version": version,
                "description": kernel_config["description"],
                "docker_image": kernel_config["docker_image"],
                "headers_package": kernel_config["headers_package"]
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error setting kernel version: {str(e)}")


@app.get("/api/kernel-versions/{version}")
async def get_kernel_version_info(version: str):
    """Get detailed information about a specific kernel version."""
    try:
        config_manager = DefaultConfigurationManager()
        available_versions = config_manager.get_available_kernel_versions()
        
        if version not in available_versions:
            raise HTTPException(
                status_code=404, 
                detail=f"Kernel version '{version}' not found. Available: {available_versions}"
            )
        
        kernel_config = config_manager.get_kernel_version_config(version)
        current_version = config_manager.load_config().get("compilation", {}).get("kernel_version", "5.15")
        
        return {
            "status": "ok",
            "version_info": {
                "version": version,
                "description": kernel_config["description"],
                "docker_image": kernel_config["docker_image"],
                "headers_package": kernel_config["headers_package"],
                "is_current": version == current_version
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting kernel version info: {str(e)}")


@app.get("/api/architectures")
async def get_architectures():
    """Get available target architectures."""
    try:
        config_manager = DefaultConfigurationManager()
        config = config_manager.load_config()
        compilation_config = config.get("compilation", {})
        
        available_architectures = compilation_config.get("available_architectures", ["x86_64"])
        current_architecture = compilation_config.get("target_architecture", "x86_64")
        cross_compile_toolchains = compilation_config.get("cross_compile_toolchains", {})
        
        architectures_info = []
        arch_descriptions = {
            "x86_64": "Intel/AMD 64-bit (x86_64)",
            "arm64": "ARM 64-bit (AArch64)",
            "arm": "ARM 32-bit",
            "riscv64": "RISC-V 64-bit"
        }
        
        for arch in available_architectures:
            architectures_info.append({
                "architecture": arch,
                "description": arch_descriptions.get(arch, f"{arch} architecture"),
                "cross_compile_prefix": cross_compile_toolchains.get(arch, ""),
                "is_current": arch == current_architecture
            })
        
        return {
            "status": "ok",
            "current_architecture": current_architecture,
            "available_architectures": architectures_info
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting architectures: {str(e)}")


@app.post("/api/architectures/set")
async def set_target_architecture(request: dict):
    """Set the default target architecture."""
    try:
        architecture = request.get("architecture")
        if not architecture:
            raise HTTPException(status_code=400, detail="Architecture is required")
        
        config_manager = DefaultConfigurationManager()
        config = config_manager.load_config()
        available_architectures = config.get("compilation", {}).get("available_architectures", ["x86_64"])
        
        if architecture not in available_architectures:
            raise HTTPException(
                status_code=400, 
                detail=f"Unsupported architecture '{architecture}'. Available: {available_architectures}"
            )
        
        # Update config
        config["compilation"]["target_architecture"] = architecture
        
        # Save config
        if not config_manager.save_config(config):
            raise HTTPException(status_code=500, detail="Failed to save configuration")
        
        # Get architecture info
        cross_compile_toolchains = config.get("compilation", {}).get("cross_compile_toolchains", {})
        arch_descriptions = {
            "x86_64": "Intel/AMD 64-bit (x86_64)",
            "arm64": "ARM 64-bit (AArch64)",
            "arm": "ARM 32-bit",
            "riscv64": "RISC-V 64-bit"
        }
        
        return {
            "status": "ok",
            "message": f"Successfully set default target architecture to {architecture}",
            "architecture_info": {
                "architecture": architecture,
                "description": arch_descriptions.get(architecture, f"{architecture} architecture"),
                "cross_compile_prefix": cross_compile_toolchains.get(architecture, "")
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error setting target architecture: {str(e)}")


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