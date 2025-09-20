/**
 * Results browsing functionality for Linux Driver Evaluation Framework
 */

class ResultsManager {
    constructor() {
        this.evaluations = [];
        this.filteredEvaluations = [];
        this.refreshInterval = null;
        
        this.initializeElements();
        this.setupEventListeners();
        this.loadEvaluations();
        this.startAutoRefresh();
    }

    initializeElements() {
        this.searchInput = document.getElementById('searchInput');
        this.statusFilter = document.getElementById('statusFilter');
        this.refreshBtn = document.getElementById('refreshBtn');
        this.resultsTableBody = document.getElementById('resultsTableBody');
        this.emptyState = document.getElementById('emptyState');
        this.loadingState = document.getElementById('loadingState');
        this.resultModal = new bootstrap.Modal(document.getElementById('resultModal'));
        this.resultContent = document.getElementById('resultContent');
        this.downloadReportBtn = document.getElementById('downloadReportBtn');
    }

    setupEventListeners() {
        // Search functionality
        this.searchInput.addEventListener('input', 
            utils.debounce(() => this.filterEvaluations(), 300)
        );

        // Status filter
        this.statusFilter.addEventListener('change', () => this.filterEvaluations());

        // Refresh button
        this.refreshBtn.addEventListener('click', () => this.loadEvaluations());

        // Download report button
        this.downloadReportBtn.addEventListener('click', () => this.downloadCurrentReport());

        // Check for specific evaluation ID in URL
        const urlParams = new URLSearchParams(window.location.search);
        const evaluationId = urlParams.get('id');
        if (evaluationId) {
            setTimeout(() => this.showEvaluationDetails(evaluationId), 1000);
        }
    }

    async loadEvaluations() {
        try {
            this.showLoading(true);
            
            const evaluations = await utils.apiRequest('/evaluations');
            this.evaluations = evaluations.sort((a, b) => 
                new Date(b.timestamp || 0) - new Date(a.timestamp || 0)
            );
            
            this.filterEvaluations();
            this.showLoading(false);
            
        } catch (error) {
            console.error('Failed to load evaluations:', error);
            utils.showToast('Failed to load evaluations', 'danger');
            this.showLoading(false);
        }
    }

    filterEvaluations() {
        const searchTerm = this.searchInput.value.toLowerCase();
        const statusFilter = this.statusFilter.value;

        this.filteredEvaluations = this.evaluations.filter(evaluation => {
            const matchesSearch = !searchTerm || 
                evaluation.id.toLowerCase().includes(searchTerm) ||
                (evaluation.message && evaluation.message.toLowerCase().includes(searchTerm));
            
            const matchesStatus = !statusFilter || evaluation.status === statusFilter;
            
            return matchesSearch && matchesStatus;
        });

        this.renderEvaluations();
    }

    renderEvaluations() {
        if (this.filteredEvaluations.length === 0) {
            this.resultsTableBody.innerHTML = '';
            this.emptyState.style.display = 'block';
            return;
        }

        this.emptyState.style.display = 'none';
        
        this.resultsTableBody.innerHTML = this.filteredEvaluations.map(evaluation => {
            const overallScore = evaluation.result?.overall_score;
            const grade = evaluation.result?.grade;
            
            return `
                <tr class="fade-in" data-evaluation-id="${evaluation.id}">
                    <td>
                        <code class="text-primary">${evaluation.id.substring(0, 8)}...</code>
                    </td>
                    <td>${utils.getStatusBadge(evaluation.status)}</td>
                    <td>${utils.getProgressBar(evaluation.progress, evaluation.status)}</td>
                    <td>
                        ${overallScore !== undefined ? 
                            `<span class="score-display">${overallScore.toFixed(1)}</span>` : 
                            '<span class="text-muted">N/A</span>'
                        }
                    </td>
                    <td>${utils.getGradeBadge(grade)}</td>
                    <td>
                        <small class="text-muted">${evaluation.message || 'No message'}</small>
                    </td>
                    <td>
                        <div class="btn-group btn-group-sm">
                            ${evaluation.status === 'completed' ? 
                                `<button class="btn btn-outline-primary view-details-btn" 
                                         data-evaluation-id="${evaluation.id}" title="View Details">
                                    <i class="fas fa-eye"></i>
                                </button>` : ''
                            }
                            ${evaluation.status === 'running' ? 
                                `<button class="btn btn-outline-info refresh-status-btn" 
                                         data-evaluation-id="${evaluation.id}" title="Refresh Status">
                                    <i class="fas fa-sync-alt"></i>
                                </button>` : ''
                            }
                        </div>
                    </td>
                </tr>
            `;
        }).join('');

        // Add event listeners to action buttons
        this.resultsTableBody.querySelectorAll('.view-details-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const evaluationId = e.currentTarget.dataset.evaluationId;
                this.showEvaluationDetails(evaluationId);
            });
        });

        this.resultsTableBody.querySelectorAll('.refresh-status-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const evaluationId = e.currentTarget.dataset.evaluationId;
                this.refreshEvaluationStatus(evaluationId);
            });
        });
    }

    async showEvaluationDetails(evaluationId) {
        try {
            const result = await utils.apiRequest(`/results/${evaluationId}`);
            this.currentEvaluationResult = result;
            
            this.resultContent.innerHTML = this.renderEvaluationDetails(result);
            this.resultModal.show();
            
        } catch (error) {
            console.error('Failed to load evaluation details:', error);
            utils.showToast('Failed to load evaluation details', 'danger');
        }
    }

    renderEvaluationDetails(result) {
        const dimensionScores = result.dimension_scores || {};
        
        return `
            <div class="row">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-chart-pie me-2"></i>Overall Score</h5>
                        </div>
                        <div class="card-body text-center">
                            <div class="display-4 text-primary mb-2">${result.overall_score?.toFixed(1) || 'N/A'}</div>
                            <div class="mb-3">${utils.getGradeBadge(result.grade)}</div>
                            <div class="text-muted">
                                <small>
                                    <i class="fas fa-bug me-1"></i>${result.summary?.total_issues || 0} total issues<br>
                                    <i class="fas fa-exclamation-triangle me-1"></i>${result.summary?.critical_issues || 0} critical issues<br>
                                    <i class="fas fa-compile me-1"></i>Compilation: ${result.summary?.compilation_status ? 'Success' : 'Failed'}
                                </small>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-tasks me-2"></i>Dimension Scores</h5>
                        </div>
                        <div class="card-body">
                            ${this.renderDimensionScores(dimensionScores)}
                        </div>
                    </div>
                </div>
            </div>
            
            ${result.detailed_findings && result.detailed_findings.length > 0 ? `
                <div class="card mt-3 findings-section">
                    <div class="card-header">
                        <h5><i class="fas fa-list me-2"></i>Detailed Findings</h5>
                        <small class="text-muted">Grouped by category and sorted by severity</small>
                    </div>
                    <div class="card-body">
                        ${this.renderDetailedFindings(result.detailed_findings)}
                    </div>
                </div>
            ` : ''}
            
            ${result.recommendations && result.recommendations.length > 0 ? `
                <div class="card mt-3">
                    <div class="card-header">
                        <h5><i class="fas fa-lightbulb me-2"></i>Recommendations</h5>
                    </div>
                    <div class="card-body">
                        ${this.renderRecommendations(result.recommendations)}
                    </div>
                </div>
            ` : ''}
        `;
    }

    renderDimensionScores(scores) {
        const dimensions = [
            { key: 'correctness', label: 'Correctness', weight: '40%', icon: 'fas fa-check-circle' },
            { key: 'security', label: 'Security', weight: '25%', icon: 'fas fa-shield-alt' },
            { key: 'code_quality', label: 'Code Quality', weight: '20%', icon: 'fas fa-code' },
            { key: 'performance', label: 'Performance', weight: '10%', icon: 'fas fa-tachometer-alt' },
            { key: 'advanced_features', label: 'Advanced Features', weight: '5%', icon: 'fas fa-star' }
        ];

        return dimensions.map(dim => {
            const score = scores[dim.key];
            const progressWidth = score !== undefined ? (score * 10) : 0;
            const progressClass = score >= 8 ? 'bg-success' : score >= 6 ? 'bg-warning' : 'bg-danger';
            
            return `
                <div class="mb-3">
                    <div class="d-flex justify-content-between align-items-center mb-1">
                        <span><i class="${dim.icon} me-2"></i>${dim.label}</span>
                        <small class="text-muted">${dim.weight}</small>
                    </div>
                    <div class="progress mb-1" style="height: 20px;">
                        <div class="progress-bar ${progressClass}" style="width: ${progressWidth}%">
                            ${score !== undefined ? score.toFixed(1) : 'N/A'}
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    }

    renderDetailedFindings(findings) {
        if (!findings || findings.length === 0) {
            return '<div class="text-muted text-center py-3">No findings to display</div>';
        }

        // Group findings by category and sort by severity
        const categorizedFindings = this.categorizeAndSortFindings(findings);
        
        return Object.entries(categorizedFindings).map(([category, categoryFindings]) => {
            const categoryInfo = this.getCategoryInfo(category);
            const totalCount = categoryFindings.length;
            const criticalCount = categoryFindings.filter(f => f.severity === 'critical').length;
            const highCount = categoryFindings.filter(f => f.severity === 'high').length;
            
            return `
                <div class="card mb-3">
                    <div class="card-header findings-category-header" data-bs-toggle="collapse" data-bs-target="#findings-${category}" 
                         aria-expanded="true">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <i class="${categoryInfo.icon} me-2"></i>
                                <strong>${categoryInfo.label}</strong>
                                <small class="text-muted ms-2">(${totalCount} issue${totalCount !== 1 ? 's' : ''})</small>
                            </div>
                            <div class="d-flex align-items-center">
                                ${criticalCount > 0 ? `<span class="badge bg-danger me-1">${criticalCount} Critical</span>` : ''}
                                ${highCount > 0 ? `<span class="badge bg-warning me-1">${highCount} High</span>` : ''}
                                <i class="fas fa-chevron-down"></i>
                            </div>
                        </div>
                    </div>
                    <div class="collapse show" id="findings-${category}">
                        <div class="card-body">
                            ${this.renderCategoryFindings(categoryFindings)}
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    }

    categorizeAndSortFindings(findings) {
        // Group findings by category based on finding type
        const categorized = {};
        
        findings.forEach(finding => {
            // Determine category from finding type
            let category = 'other';
            
            const findingType = finding.type.toLowerCase();
            
            // Security-related findings
            if (findingType.includes('buffer') || findingType.includes('overflow') || 
                findingType.includes('race_condition') || findingType.includes('condition') ||
                findingType.includes('vulnerability') || findingType.includes('unsafe') ||
                findingType.includes('security') || findingType.includes('array_access') ||
                findingType.includes('injection') || findingType.includes('dangerous_function')) {
                category = 'security';
            }
            // Correctness-related findings  
            else if (findingType.includes('memory') || findingType.includes('leak') ||
                     findingType.includes('api') || findingType.includes('misuse') ||
                     findingType.includes('null') || findingType.includes('pointer') ||
                     findingType.includes('semantic') || findingType.includes('logic') ||
                     findingType.includes('correctness') || findingType.includes('resource') ||
                     findingType.includes('allocation') || findingType.includes('deallocation')) {
                category = 'correctness';
            }
            // Code quality findings
            else if (findingType.includes('style') || findingType.includes('format') || 
                     findingType.includes('complexity') || findingType.includes('missing_function_doc') ||
                     findingType.includes('naming') || findingType.includes('checkpatch') ||
                     findingType.includes('violation') || findingType.includes('coding') ||
                     findingType.includes('maintainability') || findingType.includes('readability')) {
                category = 'code_quality';
            }
            // Performance findings
            else if (findingType.includes('performance') || findingType.includes('efficiency') || 
                     findingType.includes('algorithm') || findingType.includes('optimization') ||
                     findingType.includes('slow') || findingType.includes('bottleneck') ||
                     findingType.includes('complexity') && findingType.includes('o(')) {
                category = 'performance';
            }
            // Compilation findings
            else if (findingType.includes('compil') || findingType.includes('build') || 
                     findingType.includes('syntax') || findingType.includes('parse') ||
                     findingType.includes('warning') || findingType.includes('error')) {
                category = 'compilation';
            }
            // Advanced features
            else if (findingType.includes('power') || findingType.includes('device_tree') || 
                     findingType.includes('interrupt') || findingType.includes('advanced') ||
                     findingType.includes('feature') || findingType.includes('management')) {
                category = 'advanced_features';
            }
            
            if (!categorized[category]) {
                categorized[category] = [];
            }
            categorized[category].push(finding);
        });

        // Sort findings within each category by severity
        const severityOrder = { 'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4 };
        
        Object.keys(categorized).forEach(category => {
            categorized[category].sort((a, b) => {
                const severityA = severityOrder[a.severity] ?? 5;
                const severityB = severityOrder[b.severity] ?? 5;
                if (severityA !== severityB) {
                    return severityA - severityB;
                }
                // If same severity, sort by line number
                return (a.line || 0) - (b.line || 0);
            });
        });

        // Sort categories by priority (most critical issues first)
        const categoryOrder = ['security', 'correctness', 'compilation', 'code_quality', 'performance', 'advanced_features', 'other'];
        const sortedCategorized = {};
        
        categoryOrder.forEach(category => {
            if (categorized[category] && categorized[category].length > 0) {
                sortedCategorized[category] = categorized[category];
            }
        });

        return sortedCategorized;
    }

    getCategoryInfo(category) {
        const categoryInfo = {
            'compilation': {
                label: 'Compilation & Build',
                icon: 'fas fa-hammer',
                description: 'Issues related to code compilation and build process'
            },
            'correctness': {
                label: 'Correctness & Logic',
                icon: 'fas fa-check-circle',
                description: 'Semantic errors, API misuse, and logical issues'
            },
            'security': {
                label: 'Security & Safety',
                icon: 'fas fa-shield-alt',
                description: 'Security vulnerabilities and safety concerns'
            },
            'code_quality': {
                label: 'Code Quality & Style',
                icon: 'fas fa-code',
                description: 'Coding style, complexity, and maintainability issues'
            },
            'performance': {
                label: 'Performance & Efficiency',
                icon: 'fas fa-tachometer-alt',
                description: 'Performance bottlenecks and efficiency concerns'
            },
            'advanced_features': {
                label: 'Advanced Features',
                icon: 'fas fa-star',
                description: 'Advanced kernel features and best practices'
            },
            'other': {
                label: 'Other Issues',
                icon: 'fas fa-exclamation-triangle',
                description: 'Miscellaneous findings'
            }
        };

        return categoryInfo[category] || categoryInfo['other'];
    }

    renderCategoryFindings(findings) {
        return findings.map(finding => {
            const severityClass = {
                critical: 'danger',
                high: 'warning', 
                medium: 'info',
                low: 'secondary',
                info: 'light'
            }[finding.severity] || 'secondary';

            const severityIcon = {
                critical: 'fas fa-exclamation-circle',
                high: 'fas fa-exclamation-triangle',
                medium: 'fas fa-info-circle',
                low: 'fas fa-minus-circle',
                info: 'fas fa-info'
            }[finding.severity] || 'fas fa-question-circle';

            return `
                <div class="alert alert-${severityClass} mb-2">
                    <div class="d-flex justify-content-between align-items-start">
                        <div class="flex-grow-1">
                            <div class="d-flex align-items-center mb-1">
                                <i class="${severityIcon} me-2"></i>
                                <strong>${finding.type}</strong>
                                ${finding.file ? `<small class="text-muted ms-2">
                                    <i class="fas fa-file-code me-1"></i>${finding.file}:${finding.line || '?'}
                                </small>` : ''}
                            </div>
                            <div class="finding-message">${finding.message}</div>
                            ${finding.recommendation ? `
                                <div class="mt-2 p-2 bg-light rounded">
                                    <i class="fas fa-lightbulb me-1 text-warning"></i>
                                    <strong>Recommendation:</strong> ${finding.recommendation}
                                </div>
                            ` : ''}
                        </div>
                        <span class="badge bg-${severityClass} ms-2">${finding.severity.toUpperCase()}</span>
                    </div>
                </div>
            `;
        }).join('');
    }

    renderRecommendations(recommendations) {
        return recommendations.map(rec => `
            <div class="alert alert-info">
                <i class="fas fa-lightbulb me-2"></i>${rec}
            </div>
        `).join('');
    }

    async refreshEvaluationStatus(evaluationId) {
        try {
            const status = await utils.apiRequest(`/status/${evaluationId}`);
            
            // Update the evaluation in our local array
            const index = this.evaluations.findIndex(e => e.id === evaluationId);
            if (index !== -1) {
                this.evaluations[index] = status;
                this.filterEvaluations();
            }
            
        } catch (error) {
            console.error('Failed to refresh status:', error);
            utils.showToast('Failed to refresh status', 'danger');
        }
    }

    downloadCurrentReport() {
        if (!this.currentEvaluationResult) return;
        
        const dataStr = JSON.stringify(this.currentEvaluationResult, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        
        const link = document.createElement('a');
        link.href = URL.createObjectURL(dataBlob);
        link.download = `evaluation_report_${this.currentEvaluationResult.evaluation_id || 'unknown'}.json`;
        link.click();
        
        URL.revokeObjectURL(link.href);
    }

    showLoading(show) {
        this.loadingState.style.display = show ? 'block' : 'none';
        if (!show && this.filteredEvaluations.length === 0) {
            this.emptyState.style.display = 'block';
        }
    }

    startAutoRefresh() {
        // Refresh every 30 seconds if there are running evaluations
        this.refreshInterval = setInterval(() => {
            const hasRunningEvaluations = this.evaluations.some(e => 
                e.status === 'running' || e.status === 'pending'
            );
            
            if (hasRunningEvaluations) {
                this.loadEvaluations();
            }
        }, 30000);
    }

    destroy() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
        }
    }
}

// Initialize results manager when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.resultsManager = new ResultsManager();
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (window.resultsManager) {
        window.resultsManager.destroy();
    }
});