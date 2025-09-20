/**
 * File upload functionality for Linux Driver Evaluation Framework
 */

class FileUploadManager {
    constructor() {
        this.selectedFiles = new Map();
        this.currentEvaluationId = null;
        this.progressInterval = null;
        
        this.initializeElements();
        this.setupEventListeners();
    }

    initializeElements() {
        this.dropZone = document.getElementById('dropZone');
        this.fileInput = document.getElementById('fileInput');
        this.uploadForm = document.getElementById('uploadForm');
        this.submitBtn = document.getElementById('submitBtn');
        this.selectedFilesDiv = document.getElementById('selectedFiles');
        this.fileList = document.getElementById('fileList');
        this.progressSection = document.getElementById('progressSection');
        this.progressBar = document.getElementById('progressBar');
        this.progressMessage = document.getElementById('progressMessage');
        this.evaluationIdDiv = document.getElementById('evaluationId');
        this.resultsSection = document.getElementById('resultsSection');
        this.errorSection = document.getElementById('errorSection');
        this.errorMessage = document.getElementById('errorMessage');
        this.viewResultsBtn = document.getElementById('viewResultsBtn');
    }

    setupEventListeners() {
        // File input change
        this.fileInput.addEventListener('change', (e) => {
            this.handleFileSelection(e.target.files);
        });

        // Drag and drop events
        this.dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            this.dropZone.classList.add('dragover');
        });

        this.dropZone.addEventListener('dragleave', (e) => {
            e.preventDefault();
            this.dropZone.classList.remove('dragover');
        });

        this.dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            this.dropZone.classList.remove('dragover');
            this.handleFileSelection(e.dataTransfer.files);
        });

        // Form submission
        this.uploadForm.addEventListener('submit', (e) => {
            e.preventDefault();
            this.submitFiles();
        });

        // View results button
        this.viewResultsBtn.addEventListener('click', () => {
            if (this.currentEvaluationId) {
                window.location.href = `/results?id=${this.currentEvaluationId}`;
            }
        });

        // Sample driver buttons
        document.querySelectorAll('.sample-driver-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const driverName = e.currentTarget.dataset.driver;
                this.loadSampleDriver(driverName);
            });
        });

        // Clear samples button
        document.getElementById('clearSamplesBtn').addEventListener('click', () => {
            this.clearSampleDrivers();
        });
    }

    handleFileSelection(files) {
        const validFiles = Array.from(files).filter(file => {
            if (!file.name.endsWith('.c')) {
                utils.showToast(`File ${file.name} is not a .c file and will be ignored.`, 'warning');
                return false;
            }
            if (file.size > 10 * 1024 * 1024) { // 10MB limit
                utils.showToast(`File ${file.name} is too large (max 10MB).`, 'warning');
                return false;
            }
            return true;
        });

        validFiles.forEach(file => {
            this.selectedFiles.set(file.name, file);
        });

        this.updateFileList();
        this.updateSubmitButton();
    }

    updateFileList() {
        if (this.selectedFiles.size === 0) {
            this.selectedFilesDiv.style.display = 'none';
            return;
        }

        this.selectedFilesDiv.style.display = 'block';
        this.fileList.innerHTML = '';

        this.selectedFiles.forEach((file, filename) => {
            const fileItem = document.createElement('div');
            fileItem.className = 'file-item slide-in';
            fileItem.innerHTML = `
                <div class="file-info">
                    <i class="fas fa-file-code file-icon"></i>
                    <span class="file-name">${filename}</span>
                    <span class="file-size">${utils.formatFileSize(file.size)}</span>
                </div>
                <i class="fas fa-times remove-file" data-filename="${filename}" title="Remove file"></i>
            `;

            // Add remove functionality
            const removeBtn = fileItem.querySelector('.remove-file');
            removeBtn.addEventListener('click', () => {
                this.removeFile(filename);
            });

            this.fileList.appendChild(fileItem);
        });
    }

    removeFile(filename) {
        this.selectedFiles.delete(filename);
        this.updateFileList();
        this.updateSubmitButton();
    }

    updateSubmitButton() {
        this.submitBtn.disabled = this.selectedFiles.size === 0;
    }

    async submitFiles() {
        if (this.selectedFiles.size === 0) {
            utils.showToast('Please select at least one file.', 'warning');
            return;
        }

        try {
            this.setSubmissionState('submitting');

            // Create FormData
            const formData = new FormData();
            this.selectedFiles.forEach((file) => {
                formData.append('files', file);
            });

            // Submit files
            const response = await fetch('/api/submit', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.detail || 'Submission failed');
            }

            const result = await response.json();
            this.currentEvaluationId = result.evaluation_id;

            this.setSubmissionState('submitted');
            this.startProgressTracking();

        } catch (error) {
            console.error('Submission error:', error);
            this.showError(error.message);
            this.setSubmissionState('idle');
        }
    }

    setSubmissionState(state) {
        const states = {
            idle: () => {
                this.submitBtn.disabled = this.selectedFiles.size === 0;
                this.submitBtn.innerHTML = '<i class="fas fa-play me-2"></i>Start Evaluation';
                this.progressSection.style.display = 'none';
                this.resultsSection.style.display = 'none';
                this.errorSection.style.display = 'none';
            },
            submitting: () => {
                this.submitBtn.disabled = true;
                this.submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Submitting...';
            },
            submitted: () => {
                this.submitBtn.disabled = true;
                this.submitBtn.innerHTML = '<i class="fas fa-check me-2"></i>Submitted';
                this.progressSection.style.display = 'block';
                this.evaluationIdDiv.textContent = `Evaluation ID: ${this.currentEvaluationId}`;
            }
        };

        if (states[state]) {
            states[state]();
        }
    }

    startProgressTracking() {
        if (!this.currentEvaluationId) return;

        this.progressInterval = setInterval(async () => {
            try {
                const status = await utils.apiRequest(`/status/${this.currentEvaluationId}`);
                this.updateProgress(status);

                if (status.status === 'completed') {
                    this.handleCompletion(status);
                } else if (status.status === 'failed') {
                    this.handleFailure(status);
                }
            } catch (error) {
                console.error('Progress tracking error:', error);
                this.handleFailure({ message: 'Failed to track progress' });
            }
        }, 2000); // Poll every 2 seconds
    }

    updateProgress(status) {
        this.progressBar.style.width = `${status.progress}%`;
        this.progressBar.textContent = `${status.progress}%`;
        this.progressMessage.textContent = status.message;

        // Update progress bar color based on status
        this.progressBar.className = 'progress-bar progress-bar-striped progress-bar-animated';
        if (status.status === 'failed') {
            this.progressBar.classList.add('bg-danger');
        } else if (status.status === 'completed') {
            this.progressBar.classList.remove('progress-bar-animated');
            this.progressBar.classList.add('bg-success');
        }
    }

    handleCompletion(status) {
        if (this.progressInterval) {
            clearInterval(this.progressInterval);
            this.progressInterval = null;
        }

        this.progressSection.style.display = 'none';
        this.resultsSection.style.display = 'block';
        this.resultsSection.classList.add('fade-in');

        utils.showToast('Evaluation completed successfully!', 'success');
    }

    handleFailure(status) {
        if (this.progressInterval) {
            clearInterval(this.progressInterval);
            this.progressInterval = null;
        }

        this.showError(status.message || 'Evaluation failed');
        this.setSubmissionState('idle');
    }

    showError(message) {
        this.errorMessage.textContent = message;
        this.errorSection.style.display = 'block';
        this.errorSection.classList.add('fade-in');
        this.progressSection.style.display = 'none';
        
        utils.showToast(message, 'danger');
    }

    async loadSampleDriver(driverName) {
        try {
            // Show loading state
            const btn = document.querySelector(`[data-driver="${driverName}"]`);
            const originalContent = btn.innerHTML;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Loading...';
            btn.disabled = true;

            // Fetch sample driver content
            const response = await utils.apiRequest(`/sample-drivers/${driverName}`);
            
            // Create a File-like object from the content
            const blob = new Blob([response.content], { type: 'text/plain' });
            const file = new File([blob], response.filename, { type: 'text/plain' });
            
            // Add to selected files
            this.selectedFiles.set(response.filename, file);
            this.updateFileList();
            this.updateSubmitButton();
            
            // Restore button
            btn.innerHTML = originalContent;
            btn.disabled = false;
            
            // Show success message
            utils.showToast(`Sample driver "${response.filename}" loaded successfully!`, 'success');
            
            // Highlight the selected button temporarily
            btn.classList.add('btn-success');
            btn.classList.remove('btn-outline-success', 'btn-outline-info', 'btn-outline-primary', 'btn-outline-warning');
            setTimeout(() => {
                btn.classList.remove('btn-success');
                btn.classList.add('btn-outline-success');
            }, 2000);
            
        } catch (error) {
            console.error('Failed to load sample driver:', error);
            utils.showToast(`Failed to load sample driver: ${error.message}`, 'danger');
            
            // Restore button on error
            const btn = document.querySelector(`[data-driver="${driverName}"]`);
            btn.innerHTML = btn.innerHTML.replace('<i class="fas fa-spinner fa-spin me-2"></i>Loading...', btn.dataset.originalContent || 'Load Sample');
            btn.disabled = false;
        }
    }

    clearSampleDrivers() {
        // Remove all sample driver files
        const sampleFiles = ['simple_hello_driver.c', 'demo_driver.c', 'network_driver_sample.c', 'problematic_driver.c'];
        let removedCount = 0;
        
        sampleFiles.forEach(filename => {
            if (this.selectedFiles.has(filename)) {
                this.selectedFiles.delete(filename);
                removedCount++;
            }
        });
        
        if (removedCount > 0) {
            this.updateFileList();
            this.updateSubmitButton();
            utils.showToast(`Removed ${removedCount} sample driver(s)`, 'info');
            
            // Reset sample driver button states
            document.querySelectorAll('.sample-driver-btn').forEach(btn => {
                btn.classList.remove('btn-success');
                const originalClasses = ['btn-outline-success', 'btn-outline-info', 'btn-outline-primary', 'btn-outline-warning'];
                btn.className = btn.className.split(' ').filter(cls => !cls.startsWith('btn-')).join(' ') + ' btn w-100 sample-driver-btn';
                if (btn.dataset.driver === 'simple_hello') btn.classList.add('btn-outline-success');
                else if (btn.dataset.driver === 'character_device') btn.classList.add('btn-outline-info');
                else if (btn.dataset.driver === 'network_device') btn.classList.add('btn-outline-primary');
                else if (btn.dataset.driver === 'problematic') btn.classList.add('btn-outline-warning');
            });
        } else {
            utils.showToast('No sample drivers to remove', 'info');
        }
    }

    reset() {
        this.selectedFiles.clear();
        this.currentEvaluationId = null;
        
        if (this.progressInterval) {
            clearInterval(this.progressInterval);
            this.progressInterval = null;
        }

        this.setSubmissionState('idle');
        this.updateFileList();
        
        // Reset file input
        this.fileInput.value = '';
        
        // Reset sample driver buttons
        this.clearSampleDrivers();
    }
}

// Initialize upload manager when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.uploadManager = new FileUploadManager();
});