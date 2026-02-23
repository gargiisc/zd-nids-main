/**
 * Federated Clients Real-Time Dashboard Module
 * ============================================
 * Handles real-time updates via Server-Sent Events (SSE)
 * and manages the federated clients dashboard UI.
 */

class FederatedClientsManager {
    constructor() {
        this.clients = new Map();
        this.clientStats = {};
        this.eventSource = null;
        this.updateInterval = null;
        this.isConnected = false;
        this.lastUpdateTime = new Map();
        
        // DOM elements
        this.clientsGridEl = null;
        this.statsContainer = null;
        this.filterSelect = null;
        this.loadingEl = null;
        this.emptyStateEl = null;
        
        this.init();
    }
    
    /**
     * Initialize the manager and set up event listeners
     */
    init() {
        console.log('[FederatedClientsManager] Initializing...');
        
        // Get DOM elements
        this.clientsGridEl = document.getElementById('federated-clients-grid');
        this.statsContainer = document.getElementById('federated-stats-container');
        this.filterSelect = document.getElementById('federated-status-filter');
        this.loadingEl = document.getElementById('federated-clients-loading');
        this.emptyStateEl = document.getElementById('federated-clients-empty');
        
        // Skip if elements don't exist (not on federated page)
        if (!this.clientsGridEl) {
            console.log('[FederatedClientsManager] Dashboard elements not found, skipping init');
            return;
        }
        
        // Set up event listeners
        if (this.filterSelect) {
            this.filterSelect.addEventListener('change', () => this.filterAndRender());
        }
        
        // Initial data load
        this.loadClients();
        
        // Connect to SSE stream
        this.connectSSE();
        
        // Periodic refresh (fallback for SSE issues)
        this.updateInterval = setInterval(() => this.loadClients(), 30000);
        
        console.log('[FederatedClientsManager] Initialized successfully');
    }
    
    /**
     * Connect to Server-Sent Events stream for real-time updates
     */
    connectSSE() {
        if (this.eventSource) {
            this.eventSource.close();
        }
        
        console.log('[SSE] Connecting to federated clients stream...');
        
        this.eventSource = new EventSource('/api/federated-clients/stream');
        
        // Connection established
        this.eventSource.addEventListener('connection_established', (event) => {
            const data = JSON.parse(event.data);
            console.log('[SSE] Connected:', data);
            this.isConnected = true;
            this.updateConnectionStatus(true);
        });
        
        // Client updates
        this.eventSource.addEventListener('client_update', (event) => {
            const data = JSON.parse(event.data);
            console.log('[SSE] Client update:', data);
            this.handleClientUpdate(data.data);
        });
        
        // Error handling
        this.eventSource.addEventListener('error', (error) => {
            console.error('[SSE] Connection error:', error);
            if (this.eventSource.readyState === EventSource.CLOSED) {
                this.isConnected = false;
                this.updateConnectionStatus(false);
                // Attempt to reconnect after 5 seconds
                setTimeout(() => this.connectSSE(), 5000);
            }
        });
    }
    
    /**
     * Load all federated clients from API
     */
    async loadClients() {
        try {
            console.log('[API] Fetching federated clients...');
            
            const response = await fetch('/api/federated-clients/list?limit=100');
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            
            const data = await response.json();
            console.log('[API] Received clients:', data);
            
            // Update clients map
            this.clients.clear();
            if (data.clients && Array.isArray(data.clients)) {
                data.clients.forEach(client => {
                    this.clients.set(client.id, client);
                    this.lastUpdateTime.set(client.id, new Date().getTime());
                });
            }
            
            // Load stats
            await this.loadStats();
            
            // Render
            this.filterAndRender();
            
            // Hide loading
            if (this.loadingEl) this.loadingEl.style.display = 'none';
            
        } catch (error) {
            console.error('[API] Error loading clients:', error);
            this.showError('Failed to load federated clients');
        }
    }
    
    /**
     * Load aggregated federated statistics
     */
    async loadStats() {
        try {
            console.log('[API] Fetching federated stats...');
            
            const response = await fetch('/api/federated-clients/stats');
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            
            this.clientStats = await response.json();
            console.log('[API] Received stats:', this.clientStats);
            
            this.renderStats();
            
        } catch (error) {
            console.error('[API] Error loading stats:', error);
        }
    }
    
    /**
     * Handle real-time client status update from SSE
     */
    handleClientUpdate(updateData) {
        const clientId = updateData.client_id;
        const newStatus = updateData.data;
        
        // Update or create client
        if (this.clients.has(clientId)) {
            const client = this.clients.get(clientId);
            Object.assign(client, newStatus);
        } else {
            this.clients.set(clientId, newStatus);
        }
        
        this.lastUpdateTime.set(clientId, new Date().getTime());
        
        // Update single client card
        this.renderClientCard(clientId);
        
        // Update stats
        this.loadStats();
    }
    
    /**
     * Render statistics cards
     */
    renderStats() {
        if (!this.statsContainer) return;
        
        const stats = this.clientStats;
        const html = `
            <div class="federated-stat-card">
                <div class="federated-stat-label">Total Clients</div>
                <div class="federated-stat-value">${stats.total_clients || 0}</div>
                <div class="federated-stat-subvalue">${stats.online_clients || 0} online</div>
            </div>
            <div class="federated-stat-card">
                <div class="federated-stat-label">Avg Accuracy</div>
                <div class="federated-stat-value">${(stats.avg_accuracy * 100 || 0).toFixed(1)}%</div>
                <div class="federated-stat-subvalue">Global model performance</div>
            </div>
            <div class="federated-stat-card">
                <div class="federated-stat-label">Avg Loss</div>
                <div class="federated-stat-value">${(stats.avg_loss || 0).toFixed(3)}</div>
                <div class="federated-stat-subvalue">Training convergence</div>
            </div>
            <div class="federated-stat-card">
                <div class="federated-stat-label">Active Training</div>
                <div class="federated-stat-value">${stats.active_training_rounds || 0}</div>
                <div class="federated-stat-subvalue">Clients training now</div>
            </div>
            <div class="federated-stat-card">
                <div class="federated-stat-label">Total Flows</div>
                <div class="federated-stat-value">${this.formatLargeNumber(stats.total_flows_aggregated || 0)}</div>
                <div class="federated-stat-subvalue">Across all clients</div>
            </div>
            <div class="federated-stat-card">
                <div class="federated-stat-label">Attacks Detected</div>
                <div class="federated-stat-value">${this.formatLargeNumber(stats.total_attacks_detected || 0)}</div>
                <div class="federated-stat-subvalue">Federated consensus</div>
            </div>
        `;
        
        this.statsContainer.innerHTML = html;
    }
    
    /**
     * Filter clients based on status and render
     */
    filterAndRender() {
        const filter = this.filterSelect ? this.filterSelect.value : '';
        
        // Filter clients
        let filtered = Array.from(this.clients.values());
        if (filter) {
            filtered = filtered.filter(c => c.status === filter || c.connection_status === filter);
        }
        
        // Sort by status (online first), then by organization
        filtered.sort((a, b) => {
            const statusOrder = { 'online': 0, 'training': 1, 'offline': 2 };
            const aStatus = statusOrder[a.status] ?? 3;
            const bStatus = statusOrder[b.status] ?? 3;
            if (aStatus !== bStatus) return aStatus - bStatus;
            return (a.organization || '').localeCompare(b.organization || '');
        });
        
        this.render(filtered);
    }
    
    /**
     * Render all clients
     */
    render(clients) {
        if (!this.clientsGridEl) return;
        
        if (clients.length === 0) {
            this.clientsGridEl.innerHTML = `
                <div class="clients-empty-state" style="grid-column: 1/-1;">
                    <div class="clients-empty-state-icon">🔌</div>
                    <p>No federated clients connected</p>
                </div>
            `;
            return;
        }
        
        this.clientsGridEl.innerHTML = '';
        clients.forEach(client => {
            const card = this.createClientCard(client);
            this.clientsGridEl.appendChild(card);
        });
    }
    
    /**
     * Render a single client card
     */
    renderClientCard(clientId) {
        const client = this.clients.get(clientId);
        if (!client || !this.clientsGridEl) return;
        
        // Find existing card or create new one
        let cardEl = document.getElementById(`client-card-${clientId}`);
        if (!cardEl) {
            cardEl = this.createClientCard(client);
            this.clientsGridEl.appendChild(cardEl);
        } else {
            // Update existing card
            cardEl.outerHTML = this.createClientCard(client).outerHTML;
        }
    }
    
    /**
     * Create a client card element
     */
    createClientCard(client) {
        const card = document.createElement('div');
        card.id = `client-card-${client.id}`;
        card.className = `client-card fade-in ${client.status}`;
        
        const isOnline = client.is_online || (client.connection_status === 'online');
        const lastUpdate = this.formatTimeAgo(client.last_update);
        
        const html = `
            <!-- Header -->
            <div class="client-card-header">
                <div class="client-info">
                    <p class="client-organization">${this.escapeHtml(client.organization || 'Unknown')}</p>
                    <p class="client-id">ID: ${this.escapeHtml(client.id)}</p>
                </div>
                <span class="client-status-badge ${client.status}">
                    ${this.getStatusIcon(client.status)} ${this.formatStatus(client.status)}
                </span>
            </div>
            
            <!-- Metrics Grid -->
            <div class="client-metrics">
                <div class="metric-item">
                    <div class="metric-label">Round</div>
                    <div class="metric-value">${client.training_round || 0}</div>
                </div>
                <div class="metric-item">
                    <div class="metric-label">Flows</div>
                    <div class="metric-value">${this.formatLargeNumber(client.flows_processed || 0)}</div>
                </div>
                <div class="metric-item">
                    <div class="metric-label">Accuracy</div>
                    <div class="metric-value">${(client.local_accuracy * 100 || 0).toFixed(0)}<span class="metric-unit">%</span></div>
                </div>
                <div class="metric-item">
                    <div class="metric-label">Attacks</div>
                    <div class="metric-value">${client.attacks_detected || 0}</div>
                </div>
            </div>
            
            <!-- Accuracy Progress Bar -->
            <div class="progress-bar-container">
                <div class="progress-bar-label">
                    <span>Model Accuracy</span>
                    <span>${(client.local_accuracy * 100 || 0).toFixed(1)}%</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-bar-fill accuracy" style="width: ${(client.local_accuracy * 100 || 0)}%"></div>
                </div>
            </div>
            
            <!-- Epsilon (Privacy) Progress Bar -->
            <div class="progress-bar-container">
                <div class="progress-bar-label">
                    <span>Privacy Budget (ε)</span>
                    <span>${(client.epsilon_spent || 0).toFixed(2)}</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-bar-fill" style="width: ${Math.min((client.epsilon_spent || 0) * 10, 100)}%"></div>
                </div>
            </div>
            
            <!-- Footer -->
            <div class="client-card-footer">
                <span class="client-last-update">
                    <span>📍</span>
                    <span>${lastUpdate}</span>
                </span>
                <div class="client-actions">
                    <button class="client-action-btn" onclick="fedClientsMgr.showClientDetails('${client.id}')">
                        Details
                    </button>
                </div>
            </div>
        `;
        
        card.innerHTML = html;
        return card;
    }
    
    /**
     * Show detailed view for a client
     */
    async showClientDetails(clientId) {
        try {
            const response = await fetch(`/api/federated-clients/client/${clientId}`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            
            const data = await response.json();
            console.log('[API] Client details:', data);
            
            // For now, just log and show in alert
            // In production, this would open a detailed modal/drawer
            const client = data.client;
            const stats = data.statistics;
            const history = data.training_history;
            
            alert(`
Client: ${client.organization}
Organization: ${client.organization}
Status: ${data.current_status.status}
Training Round: ${data.current_status.training_round}

Statistics:
- Local Accuracy: ${(stats.local_accuracy * 100).toFixed(1)}%
- Precision: ${(stats.local_precision * 100).toFixed(1)}%
- Recall: ${(stats.local_recall * 100).toFixed(1)}%
- Total Flows: ${stats.total_flows_seen}
- Total Attacks: ${stats.total_attacks_detected}
- Privacy (ε): ${stats.epsilon_spent.toFixed(2)}

Last Training History (${history.length} rounds):
${history.slice(-5).map(h => `  Round ${h.round}: Loss=${h.loss?.toFixed(3)}, Acc=${h.accuracy?.toFixed(3)}`).join('\n')}
            `);
        } catch (error) {
            console.error('[API] Error loading client details:', error);
            alert('Failed to load client details');
        }
    }
    
    /**
     * Update connection status indicator
     */
    updateConnectionStatus(connected) {
        const indicator = document.getElementById('real-time-indicator');
        if (!indicator) return;
        
        if (connected) {
            indicator.innerHTML = '<span class="real-time-dot"></span> Real-time Connected';
            indicator.style.color = '#4ade80';
        } else {
            indicator.innerHTML = '<span style="display:inline-block;width:6px;height:6px;background:#6b7280;border-radius:50%;"></span> Reconnecting...';
            indicator.style.color = '#9ca3af';
        }
    }
    
    /**
     * Show error message
     */
    showError(message) {
        if (this.clientsGridEl) {
            this.clientsGridEl.innerHTML = `
                <div class="clients-empty-state" style="grid-column: 1/-1; color: #ef4444;">
                    <div class="clients-empty-state-icon">⚠️</div>
                    <p>${this.escapeHtml(message)}</p>
                </div>
            `;
        }
    }
    
    /**
     * Utility: Format large numbers
     */
    formatLargeNumber(num) {
        if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
        if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
        return num.toString();
    }
    
    /**
     * Utility: Format time ago
     */
    formatTimeAgo(timestamp) {
        if (!timestamp) return 'Never';
        
        const now = new Date();
        const time = new Date(timestamp);
        const diff = Math.floor((now - time) / 1000);
        
        if (diff < 60) return 'Just now';
        if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
        if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
        return Math.floor(diff / 86400) + 'd ago';
    }
    
    /**
     * Utility: Format status text
     */
    formatStatus(status) {
        const statusMap = {
            'online': 'Online',
            'offline': 'Offline',
            'training': 'Training'
        };
        return statusMap[status] || status;
    }
    
    /**
     * Utility: Get status icon
     */
    getStatusIcon(status) {
        const iconMap = {
            'online': '🟢',
            'offline': '🔴',
            'training': '🔵'
        };
        return iconMap[status] || '⚪';
    }
    
    /**
     * Utility: Escape HTML
     */
    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    /**
     * Destroy manager and cleanup
     */
    destroy() {
        if (this.eventSource) {
            this.eventSource.close();
        }
        if (this.updateInterval) {
            clearInterval(this.updateInterval);
        }
        console.log('[FederatedClientsManager] Destroyed');
    }
}

// Global instance
let fedClientsMgr = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    console.log('[Init] Starting FederatedClientsManager...');
    fedClientsMgr = new FederatedClientsManager();
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (fedClientsMgr) {
        fedClientsMgr.destroy();
    }
});
