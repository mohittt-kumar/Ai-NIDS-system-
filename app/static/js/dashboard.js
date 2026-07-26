// SOC Dashboard Chart.js & API controller
document.addEventListener('DOMContentLoaded', () => {
    // 1. Chart Initialization Helper
    const chartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                labels: { color: '#94a3b8', font: { family: 'Inter', size: 11 } }
            }
        },
        scales: {
            x: {
                grid: { color: '#1e293b' },
                ticks: { color: '#64748b', font: { family: 'Inter' } }
            },
            y: {
                grid: { color: '#1e293b' },
                ticks: { color: '#64748b', font: { family: 'Inter' } }
            }
        }
    };

    // Timeline Chart
    const ctxTimeline = document.getElementById('chart-timeline').getContext('2d');
    const chartTimeline = new Chart(ctxTimeline, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Threat Alerts Count',
                data: [],
                borderColor: '#0ea5e9',
                backgroundColor: 'rgba(14, 165, 233, 0.15)',
                borderWidth: 2,
                fill: true,
                tension: 0.3
            }]
        },
        options: chartOptions
    });

    // Attack Distribution
    const ctxDist = document.getElementById('chart-distribution').getContext('2d');
    const chartDist = new Chart(ctxDist, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: ['#ef4444', '#f97316', '#eab308', '#6366f1', '#a855f7', '#0ea5e9', '#10b981'],
                borderWidth: 1,
                borderColor: '#131b2e'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: { color: '#94a3b8', font: { family: 'Inter', size: 10 } }
                }
            }
        }
    });

    // Traffic Trends Chart (Total vs Malicious)
    const ctxTrends = document.getElementById('chart-trends').getContext('2d');
    const chartTrends = new Chart(ctxTrends, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Total Ingested',
                    data: [],
                    borderColor: '#64748b',
                    backgroundColor: 'transparent',
                    borderWidth: 1.5,
                    borderDash: [5, 5],
                    tension: 0.1
                },
                {
                    label: 'Malicious Injected',
                    data: [],
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.2
                }
            ]
        },
        options: chartOptions
    });

    // Top IPs Bar Chart (Horizontal)
    const ctxIps = document.getElementById('chart-ips').getContext('2d');
    const chartIps = new Chart(ctxIps, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Alerts',
                data: [],
                backgroundColor: 'rgba(249, 115, 22, 0.7)',
                borderColor: '#f97316',
                borderWidth: 1
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: {
                    grid: { color: '#1e293b' },
                    ticks: { color: '#64748b', stepSize: 5 }
                },
                y: {
                    grid: { display: false },
                    ticks: { color: '#94a3b8' }
                }
            }
        }
    });

    // Top Ports Chart
    const ctxPorts = document.getElementById('chart-ports').getContext('2d');
    const chartPorts = new Chart(ctxPorts, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Trigger Count',
                data: [],
                backgroundColor: 'rgba(99, 102, 241, 0.7)',
                borderColor: '#6366f1',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { display: false }, ticks: { color: '#94a3b8' } },
                y: { grid: { color: '#1e293b' }, ticks: { color: '#64748b' } }
            }
        }
    });

    // Protocols Doughnut
    const ctxProtocols = document.getElementById('chart-protocols').getContext('2d');
    const chartProtocols = new Chart(ctxProtocols, {
        type: 'polarArea',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: ['rgba(14, 165, 233, 0.6)', 'rgba(99, 102, 241, 0.6)', 'rgba(16, 185, 129, 0.6)'],
                borderColor: '#131b2e',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#94a3b8', font: { family: 'Inter', size: 10 } }
                }
            },
            scales: {
                r: {
                    angleLines: { color: '#1e293b' },
                    grid: { color: '#1e293b' },
                    pointLabels: { color: '#94a3b8' },
                    ticks: { display: false }
                }
            }
        }
    });

    // 2. Fetch and Update Dashboard Data
    function fetchDashboardData() {
        // Fetch stats cards
        fetch('/api/dashboard/stats')
            .then(res => res.json())
            .then(data => {
                document.getElementById('card-total-packets').innerText = data.total_packets.toLocaleString();
                document.getElementById('card-normal-packets').innerText = data.normal_packets.toLocaleString();
                document.getElementById('card-malicious-packets').innerText = data.malicious_packets.toLocaleString();
                document.getElementById('card-active-threats').innerText = data.active_threats.toLocaleString();
                document.getElementById('card-today-alerts').innerText = data.today_alerts.toLocaleString();
                document.getElementById('card-ai-accuracy').innerText = data.ai_accuracy;
            })
            .catch(err => console.error("Error loading dashboard card metrics: ", err));

        // Fetch charts and logs
        fetch('/api/dashboard/charts')
            .then(res => res.json())
            .then(data => {
                // Update Timeline
                chartTimeline.data.labels = data.threat_timeline.labels;
                chartTimeline.data.datasets[0].data = data.threat_timeline.data;
                chartTimeline.update();

                // Update Attack vectors distribution
                chartDist.data.labels = data.attack_distribution.labels;
                chartDist.data.datasets[0].data = data.attack_distribution.data;
                chartDist.update();

                // Update Traffic volume trends
                chartTrends.data.labels = data.traffic_trends.labels;
                chartTrends.data.datasets[0].data = data.traffic_trends.total;
                chartTrends.data.datasets[1].data = data.traffic_trends.malicious;
                chartTrends.update();

                // Update Top Source IP
                chartIps.data.labels = data.top_source_ips.labels;
                chartIps.data.datasets[0].data = data.top_source_ips.data;
                chartIps.update();

                // Update Top Ports
                chartPorts.data.labels = data.top_destination_ports.labels;
                chartPorts.data.datasets[0].data = data.top_destination_ports.data;
                chartPorts.update();

                // Update Protocols
                chartProtocols.data.labels = data.protocol_distribution.labels;
                chartProtocols.data.datasets[0].data = data.protocol_distribution.data;
                chartProtocols.update();

                // Populate Recent Alerts Table
                const tbody = document.getElementById('recent-alerts-tbody');
                tbody.innerHTML = '';

                if (data.recent_activity.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="8" class="text-center py-3 text-muted">No active threats logged recently.</td></tr>';
                    return;
                }

                data.recent_activity.forEach(alert => {
                    // Match severity colors
                    let badgeClass = 'badge-low';
                    if (alert.severity === 'Medium') badgeClass = 'badge-medium';
                    else if (alert.severity === 'High') badgeClass = 'badge-high';
                    else if (alert.severity === 'Critical') badgeClass = 'badge-critical';

                    const tr = document.createElement('tr');
                    tr.style.fontSize = '13px';
                    tr.className = alert.severity === 'Critical' ? 'border-danger-subtle bg-danger-subtle-glow' : '';
                    
                    tr.innerHTML = `
                        <td class="fw-semibold text-info">#${alert.id}</td>
                        <td class="text-muted">${alert.timestamp}</td>
                        <td class="font-monospace">${alert.src_ip}</td>
                        <td class="font-monospace">${alert.dst_ip}</td>
                        <td>
                            <i class="fa-solid fa-triangle-exclamation text-warning me-1"></i>
                            <span class="fw-semibold">${alert.attack_type}</span>
                        </td>
                        <td><span class="badge-sev ${badgeClass}">${alert.severity}</span></td>
                        <td><div class="progress bg-secondary" style="height: 6px; width: 60px;">
                            <div class="progress-bar bg-info" style="width: ${alert.confidence * 100}%"></div>
                        </div></td>
                        <td class="text-end">
                            <button class="btn btn-sm btn-outline-success py-0 px-2 me-1 resolve-btn" data-id="${alert.id}">
                                <i class="fa-solid fa-check"></i>
                            </button>
                            <button class="btn btn-sm btn-outline-danger py-0 px-2 delete-btn" data-id="${alert.id}">
                                <i class="fa-solid fa-trash-can"></i>
                            </button>
                        </td>
                    `;
                    tbody.appendChild(tr);
                });

                // Wire up actions buttons
                document.querySelectorAll('.resolve-btn').forEach(btn => {
                    btn.addEventListener('click', (e) => {
                        const id = btn.getAttribute('data-id');
                        resolveAlert(id);
                    });
                });
                document.querySelectorAll('.delete-btn').forEach(btn => {
                    btn.addEventListener('click', (e) => {
                        const id = btn.getAttribute('data-id');
                        deleteAlert(id);
                    });
                });
            })
            .catch(err => console.error("Error loading charts statistics: ", err));
    }

    function resolveAlert(id) {
        fetch(`/api/alert/${id}/resolve`, { method: 'POST' })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    showNotification(`Alert ID #${id} resolved successfully.`, 'success');
                    fetchDashboardData();
                } else {
                    showNotification("Action failed: " + data.error, "danger");
                }
            });
    }

    function deleteAlert(id) {
        if (confirm(`Are you sure you want to dismiss and delete alert ID #${id}?`)) {
            fetch(`/api/alert/${id}/delete`, { method: 'POST' })
                .then(res => res.json())
                .then(data => {
                    if (data.success) {
                        showNotification(`Alert ID #${id} deleted from active view.`, 'warning');
                        fetchDashboardData();
                    } else {
                        showNotification("Action failed: " + data.error, "danger");
                    }
                });
        }
    }

    // Connect page callback for start/stop sniffing
    window.onEngineToggle = (active) => {
        // Fetch dashboard instantly on engine status toggle
        setTimeout(fetchDashboardData, 1000);
    };

    // Initialize fetches
    fetchDashboardData();
    setInterval(fetchDashboardData, 4000); // Poll dashboard every 4 seconds
});
