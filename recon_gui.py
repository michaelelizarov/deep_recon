#!/usr/bin/env python3
"""
Web GUI for Deep Recon Tool Configuration
Provides interface for tool selection and settings
"""

from flask import Flask, render_template_string, request, jsonify, send_file
import json
import subprocess
import sys
from pathlib import Path
import threading

# Import our config manager
sys.path.insert(0, str(Path(__file__).parent))
from deep_recon_v2 import ConfigManager, TOOL_DATABASE, Colors

app = Flask(__name__)
config_manager = ConfigManager()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Deep Recon Tool - Configuration</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            opacity: 0.9;
            font-size: 1.1em;
        }
        
        .tabs {
            display: flex;
            background: #f8f9fa;
            border-bottom: 2px solid #dee2e6;
        }
        
        .tab {
            flex: 1;
            padding: 20px;
            text-align: center;
            cursor: pointer;
            background: #e9ecef;
            border-right: 1px solid #dee2e6;
            transition: all 0.3s;
            font-weight: bold;
            color: #495057;
        }
        
        .tab:hover {
            background: #d3d3d3;
        }
        
        .tab.active {
            background: white;
            color: #2a5298;
            border-bottom: 3px solid #2a5298;
        }
        
        .tab-content {
            display: none;
            padding: 30px;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .mode-selection {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .mode-card {
            border: 2px solid #dee2e6;
            border-radius: 10px;
            padding: 25px;
            cursor: pointer;
            transition: all 0.3s;
            background: white;
        }
        
        .mode-card:hover {
            border-color: #667eea;
            transform: translateY(-5px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }
        
        .mode-card.selected {
            border-color: #2a5298;
            background: #e7f3ff;
            box-shadow: 0 5px 20px rgba(42,82,152,0.2);
        }
        
        .mode-card h3 {
            color: #2a5298;
            margin-bottom: 10px;
            font-size: 1.5em;
        }
        
        .mode-card p {
            color: #666;
            line-height: 1.6;
        }
        
        .mode-badge {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            margin-top: 10px;
        }
        
        .badge-recommended {
            background: #28a745;
            color: white;
        }
        
        .badge-fast {
            background: #17a2b8;
            color: white;
        }
        
        .badge-custom {
            background: #ffc107;
            color: black;
        }
        
        .category-section {
            margin-bottom: 30px;
            border: 1px solid #dee2e6;
            border-radius: 10px;
            padding: 20px;
            background: #f8f9fa;
        }
        
        .category-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .category-header h3 {
            color: #2a5298;
            font-size: 1.3em;
        }
        
        .select-all-btn {
            padding: 8px 15px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
        }
        
        .tools-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 15px;
        }
        
        .tool-card {
            border: 2px solid #dee2e6;
            border-radius: 8px;
            padding: 15px;
            background: white;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .tool-card:hover {
            border-color: #667eea;
            box-shadow: 0 3px 10px rgba(0,0,0,0.1);
        }
        
        .tool-card.selected {
            border-color: #28a745;
            background: #d4edda;
        }
        
        .tool-card.recommended {
            border-color: #ffc107;
        }
        
        .tool-name {
            font-weight: bold;
            color: #2a5298;
            margin-bottom: 8px;
        }
        
        .tool-stats {
            display: flex;
            gap: 10px;
            margin-top: 10px;
        }
        
        .stat {
            flex: 1;
            text-align: center;
            padding: 5px;
            border-radius: 5px;
            font-size: 0.85em;
        }
        
        .stat-speed {
            background: #d1ecf1;
            color: #0c5460;
        }
        
        .stat-accuracy {
            background: #d4edda;
            color: #155724;
        }
        
        .recommended-badge {
            display: inline-block;
            padding: 3px 8px;
            background: #ffc107;
            color: black;
            border-radius: 5px;
            font-size: 0.75em;
            font-weight: bold;
            margin-left: 5px;
        }
        
        .action-buttons {
            display: flex;
            gap: 15px;
            justify-content: center;
            margin-top: 30px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 10px;
        }
        
        .btn {
            padding: 15px 40px;
            font-size: 1.1em;
            font-weight: bold;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(102,126,234,0.4);
        }
        
        .btn-success {
            background: #28a745;
            color: white;
        }
        
        .btn-danger {
            background: #dc3545;
            color: white;
        }
        
        .scan-section {
            padding: 30px;
            background: white;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: bold;
            color: #2a5298;
        }
        
        .form-group input {
            width: 100%;
            padding: 12px;
            border: 2px solid #dee2e6;
            border-radius: 8px;
            font-size: 1em;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        #scan-output {
            background: #1e1e1e;
            color: #00ff00;
            padding: 20px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            height: 400px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        
        .status-bar {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }
        
        .status-ready {
            background: #28a745;
        }
        
        .status-running {
            background: #ffc107;
            animation: pulse 1s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .alert {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        
        .alert-success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .alert-warning {
            background: #fff3cd;
            color: #856404;
            border: 1px solid #ffeaa7;
        }
        
        .alert-info {
            background: #d1ecf1;
            color: #0c5460;
            border: 1px solid #bee5eb;
        }
        
        .settings-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        
        .setting-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            border: 1px solid #dee2e6;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Deep Reconnaissance Tool v2.0</h1>
            <p>Advanced Security Scanner with Multi-Tool Support</p>
        </div>
        
        <div class="tabs">
            <div class="tab active" onclick="showTab('quick-scan')">🚀 Quick Scan</div>
            <div class="tab" onclick="showTab('tool-config')">🛠️ Tool Configuration</div>
            <div class="tab" onclick="showTab('settings')">⚙️ Settings</div>
            <div class="tab" onclick="showTab('about')">ℹ️ About</div>
        </div>
        
        <!-- Quick Scan Tab -->
        <div id="quick-scan" class="tab-content active">
            <div class="alert alert-info">
                <strong>Quick Scan Mode:</strong> Choose your scanning strategy and start reconnaissance
            </div>
            
            <div class="mode-selection">
                <div class="mode-card selected" id="mode-default" onclick="selectMode('default')">
                    <h3>🎯 Default Mode</h3>
                    <p>Uses the best and most reliable tools for each category. Recommended for most users.</p>
                    <span class="mode-badge badge-recommended">RECOMMENDED</span>
                </div>
                
                <div class="mode-card" id="mode-random" onclick="selectMode('random')">
                    <h3>🎲 Random Mode</h3>
                    <p>Randomly selects tools for variety. Good for testing different tool combinations.</p>
                    <span class="mode-badge badge-fast">EXPERIMENTAL</span>
                </div>
                
                <div class="mode-card" id="mode-custom" onclick="selectMode('custom')">
                    <h3>⚙️ Custom Mode</h3>
                    <p>Manually select specific tools. For advanced users who know their requirements.</p>
                    <span class="mode-badge badge-custom">ADVANCED</span>
                </div>
            </div>
            
            <div class="scan-section">
                <div class="form-group">
                    <label for="target-input">🎯 Target (Domain or IP)</label>
                    <input type="text" id="target-input" placeholder="example.com or 192.168.1.1" />
                </div>
                
                <div class="form-group">
                    <label for="output-input">📁 Output Directory</label>
                    <input type="text" id="output-input" value="recon_results" />
                </div>
                
                <div class="status-bar">
                    <div>
                        <span class="status-indicator status-ready" id="status-indicator"></span>
                        <strong>Status:</strong> <span id="scan-status">Ready</span>
                    </div>
                    <div>
                        <strong>Mode:</strong> <span id="current-mode">Default</span>
                    </div>
                </div>
                
                <div class="action-buttons">
                    <button class="btn btn-primary" onclick="startScan()">🚀 Start Reconnaissance</button>
                    <button class="btn btn-danger" onclick="stopScan()" id="stop-btn" style="display:none;">⏹️ Stop Scan</button>
                </div>
                
                <div id="scan-output" style="display:none;"></div>
            </div>
        </div>
        
        <!-- Tool Configuration Tab -->
        <div id="tool-config" class="tab-content">
            <div class="alert alert-warning">
                <strong>Custom Tool Selection:</strong> Select specific tools for each category. Changes apply to Custom Mode.
            </div>
            
            <div id="tool-categories"></div>
            
            <div class="action-buttons">
                <button class="btn btn-success" onclick="saveToolConfig()">💾 Save Configuration</button>
                <button class="btn btn-primary" onclick="loadDefaultTools()">🔄 Reset to Defaults</button>
            </div>
        </div>
        
        <!-- Settings Tab -->
        <div id="settings" class="tab-content">
            <h2 style="color: #2a5298; margin-bottom: 20px;">⚙️ General Settings</h2>
            
            <div class="settings-grid">
                <div class="setting-card">
                    <h3>Performance</h3>
                    <div class="form-group">
                        <label>Parallel Workers</label>
                        <input type="number" id="workers-input" value="10" min="1" max="50" />
                        <small>Number of concurrent tasks (1-50)</small>
                    </div>
                </div>
                
                <div class="setting-card">
                    <h3>Timeouts (seconds)</h3>
                    <div class="form-group">
                        <label>General Timeout</label>
                        <input type="number" id="timeout-general" value="300" min="30" max="3600" />
                    </div>
                    <div class="form-group">
                        <label>Port Scan Timeout</label>
                        <input type="number" id="timeout-port" value="600" min="60" max="3600" />
                    </div>
                    <div class="form-group">
                        <label>Vulnerability Scan Timeout</label>
                        <input type="number" id="timeout-vuln" value="900" min="60" max="3600" />
                    </div>
                </div>
            </div>
            
            <div class="action-buttons">
                <button class="btn btn-success" onclick="saveSettings()">💾 Save Settings</button>
            </div>
        </div>
        
        <!-- About Tab -->
        <div id="about" class="tab-content">
            <div class="scan-section">
                <h2 style="color: #2a5298;">About Deep Recon Tool v2.0</h2>
                <p style="margin: 20px 0; line-height: 1.8;">
                    <strong>Deep Reconnaissance Tool v2.0</strong> is an advanced security scanner that automates 
                    comprehensive reconnaissance using multiple industry-standard tools.
                </p>
                
                <h3 style="color: #2a5298; margin-top: 30px;">Features</h3>
                <ul style="line-height: 2;">
                    <li>✅ Multi-tool support (5+ tools per category)</li>
                    <li>✅ Default, Random, and Custom modes</li>
                    <li>✅ Web-based GUI for easy configuration</li>
                    <li>✅ Parallel processing for speed</li>
                    <li>✅ Comprehensive HTML reports</li>
                    <li>✅ JSON export for automation</li>
                </ul>
                
                <h3 style="color: #2a5298; margin-top: 30px;">Tool Categories</h3>
                <ul style="line-height: 2;">
                    <li>🌐 <strong>DNS Reconnaissance:</strong> Subfinder, Amass, dnsenum, dnsrecon, Assetfinder</li>
                    <li>📁 <strong>Directory Brute-forcing:</strong> FFUF, Feroxbuster, Gobuster, Dirsearch, Dirb</li>
                    <li>🔌 <strong>Port Scanning:</strong> Nmap, Rustscan, Masscan, Naabu, Unicornscan</li>
                    <li>🚨 <strong>Vulnerability Scanning:</strong> Nuclei, Nikto, WPScan, SQLMap, Dalfox</li>
                    <li>🔒 <strong>SSL/TLS Testing:</strong> testssl.sh, SSLScan, SSLyze, TLS-Sled, SSL Labs</li>
                    <li>🕷️ <strong>Web Crawling:</strong> Gospider, Katana, Hakrawler, GAU, Waybackurls</li>
                </ul>
                
                <div class="alert alert-warning" style="margin-top: 30px;">
                    <strong>⚠️ Legal Notice:</strong> Only use this tool on systems you own or have explicit 
                    permission to test. Unauthorized scanning is illegal.
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let selectedMode = 'default';
        let scanProcess = null;
        
        // Tab switching
        function showTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            
            document.getElementById(tabId).classList.add('active');
            event.target.classList.add('active');
            
            if (tabId === 'tool-config') {
                loadToolCategories();
            }
        }
        
        // Mode selection
        function selectMode(mode) {
            selectedMode = mode;
            document.querySelectorAll('.mode-card').forEach(c => c.classList.remove('selected'));
            document.getElementById(`mode-${mode}`).classList.add('selected');
            document.getElementById('current-mode').textContent = mode.charAt(0).toUpperCase() + mode.slice(1);
            
            // If custom mode, switch to tool config tab
            if (mode === 'custom') {
                showTab('tool-config');
                document.querySelectorAll('.tab')[1].classList.add('active');
            }
        }
        
        // Load tool categories
        function loadToolCategories() {
            fetch('/api/tools')
                .then(r => r.json())
                .then(data => {
                    const container = document.getElementById('tool-categories');
                    container.innerHTML = '';
                    
                    for (const [category, info] of Object.entries(data)) {
                        const section = document.createElement('div');
                        section.className = 'category-section';
                        
                        let html = `
                            <div class="category-header">
                                <h3>${info.name}</h3>
                                <button class="select-all-btn" onclick="selectAllTools('${category}')">Select All</button>
                            </div>
                            <div class="tools-grid">
                        `;
                        
                        for (const [toolId, tool] of Object.entries(info.tools)) {
                            const isRecommended = tool.recommended ? '<span class="recommended-badge">RECOMMENDED</span>' : '';
                            const isSelected = info.default.includes(toolId) ? 'selected' : '';
                            const recClass = tool.recommended ? 'recommended' : '';
                            
                            html += `
                                <div class="tool-card ${isSelected} ${recClass}" 
                                     data-category="${category}" 
                                     data-tool="${toolId}"
                                     onclick="toggleTool(this)">
                                    <div class="tool-name">${tool.name} ${isRecommended}</div>
                                    <div class="tool-stats">
                                        <div class="stat stat-speed">Speed: ${tool.speed}/5</div>
                                        <div class="stat stat-accuracy">Accuracy: ${tool.accuracy}/5</div>
                                    </div>
                                </div>
                            `;
                        }
                        
                        html += '</div>';
                        section.innerHTML = html;
                        container.appendChild(section);
                    }
                });
        }
        
        // Toggle tool selection
        function toggleTool(element) {
            element.classList.toggle('selected');
        }
        
        // Select all tools in category
        function selectAllTools(category) {
            document.querySelectorAll(`[data-category="${category}"]`).forEach(t => {
                t.classList.add('selected');
            });
        }
        
        // Save tool configuration
        function saveToolConfig() {
            const config = {};
            
            document.querySelectorAll('.category-section').forEach(section => {
                const category = section.querySelector('[data-category]').dataset.category;
                const selected = [];
                
                section.querySelectorAll('.tool-card.selected').forEach(card => {
                    selected.push(card.dataset.tool);
                });
                
                config[category] = selected;
            });
            
            fetch('/api/config/tools', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(config)
            })
            .then(r => r.json())
            .then(data => {
                alert('✅ Configuration saved successfully!');
            });
        }
        
        // Load default tools
        function loadDefaultTools() {
            fetch('/api/config/default', {method: 'POST'})
                .then(() => {
                    alert('✅ Reset to default tools');
                    loadToolCategories();
                });
        }
        
        // Save settings
        function saveSettings() {
            const settings = {
                parallel_workers: parseInt(document.getElementById('workers-input').value),
                timeouts: {
                    general: parseInt(document.getElementById('timeout-general').value),
                    port_scan: parseInt(document.getElementById('timeout-port').value),
                    vuln_scan: parseInt(document.getElementById('timeout-vuln').value)
                }
            };
            
            fetch('/api/settings', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(settings)
            })
            .then(() => alert('✅ Settings saved!'));
        }
        
        // Start scan
        function startScan() {
            const target = document.getElementById('target-input').value;
            const output = document.getElementById('output-input').value;
            
            if (!target) {
                alert('❌ Please enter a target!');
                return;
            }
            
            document.getElementById('scan-output').style.display = 'block';
            document.getElementById('scan-output').textContent = `Starting scan on ${target}...\n\n`;
            document.getElementById('stop-btn').style.display = 'inline-block';
            document.getElementById('scan-status').textContent = 'Running...';
            document.getElementById('status-indicator').className = 'status-indicator status-running';
            
            fetch('/api/scan/start', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    target: target,
                    output: output,
                    mode: selectedMode
                })
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    pollScanStatus();
                } else {
                    alert('❌ Failed to start scan: ' + data.error);
                }
            });
        }
        
        // Poll scan status
        function pollScanStatus() {
            const interval = setInterval(() => {
                fetch('/api/scan/status')
                    .then(r => r.json())
                    .then(data => {
                        const output = document.getElementById('scan-output');
                        output.textContent += data.output || '';
                        output.scrollTop = output.scrollHeight;
                        
                        if (data.completed) {
                            clearInterval(interval);
                            document.getElementById('scan-status').textContent = 'Completed';
                            document.getElementById('status-indicator').className = 'status-indicator status-ready';
                            document.getElementById('stop-btn').style.display = 'none';
                            alert('✅ Scan completed! Check output directory for results.');
                        }
                    });
            }, 2000);
        }
        
        // Stop scan
        function stopScan() {
            fetch('/api/scan/stop', {method: 'POST'})
                .then(() => {
                    document.getElementById('scan-status').textContent = 'Stopped';
                    document.getElementById('status-indicator').className = 'status-indicator status-ready';
                    document.getElementById('stop-btn').style.display = 'none';
                });
        }
        
        // Load initial configuration
        fetch('/api/config')
            .then(r => r.json())
            .then(data => {
                document.getElementById('workers-input').value = data.parallel_workers;
                document.getElementById('timeout-general').value = data.timeouts.general;
                document.getElementById('timeout-port').value = data.timeouts.port_scan;
                document.getElementById('timeout-vuln').value = data.timeouts.vuln_scan;
            });
    </script>
</body>
</html>
"""

# Global scan process variable
scan_process = None
scan_output = []

@app.route('/')
def index():
    """Main page"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/tools')
def get_tools():
    """Get all available tools"""
    return jsonify(TOOL_DATABASE)

@app.route('/api/config')
def get_config():
    """Get current configuration"""
    return jsonify(config_manager.config)

@app.route('/api/config/tools', methods=['POST'])
def update_tool_config():
    """Update tool selection"""
    selections = request.json
    config_manager.set_custom_tools(selections)
    return jsonify({"success": True})

@app.route('/api/config/default', methods=['POST'])
def reset_default():
    """Reset to default tools"""
    config_manager.set_default_tools()
    return jsonify({"success": True})

@app.route('/api/config/random', methods=['POST'])
def set_random():
    """Set random tools"""
    config_manager.set_random_tools()
    return jsonify({"success": True})

@app.route('/api/settings', methods=['POST'])
def update_settings():
    """Update general settings"""
    settings = request.json
    config_manager.config['parallel_workers'] = settings.get('parallel_workers', 10)
    config_manager.config['timeouts'] = settings.get('timeouts', {})
    config_manager.save_config()
    return jsonify({"success": True})

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Start a scan"""
    global scan_process, scan_output
    
    data = request.json
    target = data.get('target')
    output = data.get('output', 'recon_results')
    mode = data.get('mode', 'default')
    
    # Set mode
    if mode == 'random':
        config_manager.set_random_tools()
    elif mode == 'default':
        config_manager.set_default_tools()
    
    # Start scan process
    scan_output = []
    cmd = [
        sys.executable,
        'deep_recon_v2.py',
        '-t', target,
        '-o', output,
        '-m', mode
    ]
    
    try:
        scan_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        # Start thread to read output
        def read_output():
            for line in scan_process.stdout:
                scan_output.append(line)
        
        threading.Thread(target=read_output, daemon=True).start()
        
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/scan/status')
def scan_status():
    """Get scan status"""
    global scan_process, scan_output
    
    if scan_process is None:
        return jsonify({"completed": True, "output": ""})
    
    completed = scan_process.poll() is not None
    output = ''.join(scan_output[-50:])  # Last 50 lines
    
    return jsonify({
        "completed": completed,
        "output": output
    })

@app.route('/api/scan/stop', methods=['POST'])
def stop_scan():
    """Stop current scan"""
    global scan_process
    
    if scan_process:
        scan_process.terminate()
        scan_process = None
    
    return jsonify({"success": True})

def main():
    """Run web server"""
    print(f"{Colors.CYAN}Starting Web GUI...{Colors.END}")
    print(f"{Colors.GREEN}Open your browser to: http://127.0.0.1:5000{Colors.END}")
    print(f"{Colors.YELLOW}Press Ctrl+C to stop{Colors.END}\n")
    
    app.run(host='0.0.0.0', port=5000, debug=False)

if __name__ == '__main__':
    main()
