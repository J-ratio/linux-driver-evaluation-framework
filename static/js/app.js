/**
 * Main application JavaScript for Linux Driver Evaluation Framework
 */

// Global configuration
const API_BASE_URL = '/api';

// Utility functions
const utils = {
    /**
     * Format file size in human readable format
     */
    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },

    /**
     * Format timestamp to readable date
     */
    formatDate(timestamp) {
        return new Date(timestamp).toLocaleString();
    },

    /**
     * Show toast notification
     */
    showToast(message, type = 'info') {
        // Create toast element
        const toast = document.createElement('div');
        toast.className = `toast align-items-center text-white bg-${type} border-0`;
        toast.setAttribute('role', 'alert');
        toast.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">${message}</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        `;

        // Add to toast container or create one
        let toastContainer = document.getElementById('toastContainer');
        if (!toastContainer) {
            toastContainer = document.createElement('div');
            toastContainer.id = 'toastContainer';
            toastContainer.className = 'toast-container position-fixed top-0 end-0 p-3';
            toastContainer.style.zIndex = '9999';
            document.body.appendChild(toastContainer);
        }

        toastContainer.appendChild(toast);

        // Show toast
        const bsToast = new bootstrap.Toast(toast);
        bsToast.show();

        // Remove from DOM after hiding
        toast.addEventListener('hidden.bs.toast', () => {
            toast.remove();
        });
    },

    /**
     * Make API request with error handling
     */
    async apiRequest(url, options = {}) {
        try {
            const response = await fetch(API_BASE_URL + url, {
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                },
                ...options
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.detail || `HTTP ${response.status}: ${response.statusText}`);
            }

            return await response.json();
        } catch (error) {
            console.error('API request failed:', error);
            throw error;
        }
    },

    /**
     * Debounce function calls
     */
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    /**
     * Get status badge HTML
     */
    getStatusBadge(status) {
        const badges = {
            completed: '<span class="badge status-badge status-completed">Completed</span>',
            running: '<span class="badge status-badge status-running">Running</span>',
            failed: '<span class="badge status-badge status-failed">Failed</span>',
            pending: '<span class="badge status-badge status-pending">Pending</span>'
        };
        return badges[status] || `<span class="badge bg-secondary">${status}</span>`;
    },

    /**
     * Get grade badge HTML
     */
    getGradeBadge(grade) {
        if (!grade) return '<span class="badge bg-secondary">N/A</span>';
        return `<span class="badge grade-badge grade-${grade}">${grade}</span>`;
    },

    /**
     * Get progress bar HTML
     */
    getProgressBar(progress, status) {
        const progressClass = status === 'failed' ? 'bg-danger' : 'bg-primary';
        return `
            <div class="progress" style="height: 20px;">
                <div class="progress-bar ${progressClass}" role="progressbar" 
                     style="width: ${progress}%" aria-valuenow="${progress}" 
                     aria-valuemin="0" aria-valuemax="100">
                    ${progress}%
                </div>
            </div>
        `;
    }
};

// Global error handler
window.addEventListener('error', (event) => {
    console.error('Global error:', event.error);
    utils.showToast('An unexpected error occurred. Please try again.', 'danger');
});

// Global unhandled promise rejection handler
window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
    utils.showToast('An unexpected error occurred. Please try again.', 'danger');
    event.preventDefault();
});

// Export utils for use in other scripts
window.utils = utils;