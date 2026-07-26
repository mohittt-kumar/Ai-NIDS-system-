// SOC Packet Monitor logic controller
document.addEventListener('DOMContentLoaded', () => {
    let lastPacketId = 0;
    let streamInterval = null;
    let isMonitoring = false;
    
    const tbody = document.getElementById('monitor-stream-tbody');
    const toggleBtn = document.getElementById('monitor-toggle-btn');
    const clearBtn = document.getElementById('monitor-clear-btn');
    const simToggle = document.getElementById('simulation-mode-toggle');
    const counterBadge = document.getElementById('packet-counter-badge');
    
    let totalPacketsLogged = 0;

    function initMonitorState() {
        fetch('/api/packet/status')
            .then(res => res.json())
            .then(data => {
                isMonitoring = data.monitoring_active;
                simToggle.checked = data.simulation_mode;
                
                updateControlUI(isMonitoring);
                
                // Load recent logs initially
                tbody.innerHTML = '';
                if (data.packets.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="8" class="text-center py-4 text-muted">Intrusion log database is empty.</td></tr>';
                } else {
                    // Cache the highest packet ID
                    lastPacketId = data.packets.length > 0 ? Math.max(...data.packets.map(p => p.id)) : 0;
                    totalPacketsLogged = data.packets.length;
                    counterBadge.textContent = `Logged: ${totalPacketsLogged} packets`;
                    
                    data.packets.forEach(p => appendPacketRow(p, false)); // Append to bottom
                }
                
                // Toggle interval sniffing
                if (isMonitoring) {
                    startStreamPolling();
                } else {
                    stopStreamPolling();
                }
            })
            .catch(err => console.error("Error fetching monitor configuration state: ", err));
    }

    function updateControlUI(active) {
        if (active) {
            toggleBtn.className = "btn btn-danger";
            toggleBtn.innerHTML = '<i class="fa-solid fa-stop me-1"></i>Stop Monitor';
            simToggle.disabled = true; // Block change while running
        } else {
            toggleBtn.className = "btn btn-cyber";
            toggleBtn.innerHTML = '<i class="fa-solid fa-play me-1"></i>Start Monitor';
            simToggle.disabled = false;
        }
    }

    function startStreamPolling() {
        if (streamInterval) clearInterval(streamInterval);
        
        streamInterval = setInterval(() => {
            fetch(`/api/packet/stream?last_id=${lastPacketId}`)
                .then(res => res.json())
                .then(data => {
                    if (data.packets.length > 0) {
                        // Clear placeholders if database was empty
                        if (totalPacketsLogged === 0) {
                            tbody.innerHTML = '';
                        }
                        
                        // New packets found! Sort ascending to append them correctly or prepend descending
                        // Since we want newest on top, we reverse loop and prepend to top
                        const newPackets = data.packets.sort((a,b) => a.id - b.id);
                        newPackets.forEach(p => {
                            appendPacketRow(p, true); // Prepend to top
                            if (p.id > lastPacketId) {
                                lastPacketId = p.id;
                            }
                            totalPacketsLogged++;
                        });
                        
                        counterBadge.textContent = `Logged: ${totalPacketsLogged} packets`;
                    }
                })
                .catch(err => console.error("Stream polling error: ", err));
        }, 1200);
    }

    function stopStreamPolling() {
        if (streamInterval) {
            clearInterval(streamInterval);
            streamInterval = null;
        }
    }

    function appendPacketRow(pkt, prepend = true) {
        const tr = document.createElement('tr');
        tr.className = pkt.is_malicious ? 'packet-row malicious text-danger-subtle' : 'packet-row';
        tr.dataset.id = pkt.id;
        
        let protocolBadge = 'bg-secondary';
        if (pkt.protocol === 'TCP') protocolBadge = 'bg-primary';
        else if (pkt.protocol === 'UDP') protocolBadge = 'bg-info';
        else if (pkt.protocol === 'ICMP') protocolBadge = 'bg-warning text-dark';
        
        let severityTag = '';
        if (pkt.is_malicious) {
            let badgeStyle = 'badge-low';
            if (pkt.severity === 'Medium') badgeStyle = 'badge-medium';
            else if (pkt.severity === 'High') badgeStyle = 'badge-high';
            else if (pkt.severity === 'Critical') badgeStyle = 'badge-critical';
            
            severityTag = `<span class="badge-sev ${badgeStyle} px-2 py-0" style="font-size: 10px;">${pkt.prediction} [${pkt.severity}]</span>`;
        } else {
            severityTag = '<span class="text-success"><i class="fa-solid fa-check-double me-1"></i>Normal</span>';
        }

        tr.innerHTML = `
            <td class="text-info">${pkt.id}</td>
            <td class="text-muted" style="font-size: 11px;">${pkt.timestamp.split(' ')[1]}</td>
            <td>${pkt.src_ip}</td>
            <td>${pkt.dst_ip}</td>
            <td><span class="badge ${protocolBadge} text-uppercase px-2 py-1" style="font-size: 10px;">${pkt.protocol}</span></td>
            <td>${pkt.length}</td>
            <td>${severityTag}</td>
            <td class="text-muted font-monospace" style="font-size: 11px; max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                ${pkt.payload_preview}
            </td>
        `;

        if (prepend && tbody.firstChild) {
            tbody.insertBefore(tr, tbody.firstChild);
            // Throttle max visible rows to keep DOM clean (max 100 rows)
            if (tbody.children.length > 100) {
                tbody.removeChild(tbody.lastChild);
            }
        } else {
            tbody.appendChild(tr);
        }
    }

    // Start/Stop Sniffer Button Click
    toggleBtn.addEventListener('click', () => {
        const action = isMonitoring ? 'stop' : 'start';
        const bodyObj = action === 'start' ? { simulation_mode: simToggle.checked } : {};

        fetch(`/api/packet/${action}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(bodyObj)
        })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                isMonitoring = !isMonitoring;
                updateControlUI(isMonitoring);
                showNotification(isMonitoring ? "Network capture thread launched." : "Network capture thread suspended.", isMonitoring ? "success" : "warning");
                
                if (isMonitoring) {
                    startStreamPolling();
                } else {
                    stopStreamPolling();
                }
            } else {
                showNotification(`Action failed: ${data.error}`, "danger");
            }
        })
        .catch(err => console.error("Error setting monitor trigger: ", err));
    });

    // Clear logs button Click
    clearBtn.addEventListener('click', () => {
        if (confirm("Are you sure you want to flush the entire database of packet records and associated alerts? This action is irreversible.")) {
            fetch('/api/packet/clear', { method: 'POST' })
                .then(res => res.json())
                .then(data => {
                    if (data.success) {
                        showNotification("Packet logs and alerts database flushed.", "warning");
                        tbody.innerHTML = '<tr><td colspan="8" class="text-center py-4 text-muted">Intrusion log database is empty.</td></tr>';
                        lastPacketId = 0;
                        totalPacketsLogged = 0;
                        counterBadge.textContent = "Logged: 0 packets";
                    } else {
                        showNotification(`Action failed: ${data.error}`, "danger");
                    }
                })
                .catch(err => console.error("Error clearing logs: ", err));
        }
    });

    // Page-specific trigger callback for top navigation
    window.onEngineToggle = (active) => {
        isMonitoring = active;
        updateControlUI(active);
        if (active) startStreamPolling();
        else stopStreamPolling();
    };

    // Initialize state
    initMonitorState();
});
