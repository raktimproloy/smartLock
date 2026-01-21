const express = require('express');
const cors = require('cors');
const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));  // Increase limit for large device data
app.use(express.static('public'));

// Store logs and connections
let logs = [];
let deviceScans = [];  // Store complete device scans
let connectedClients = []; // For web dashboard SSE
let esp32Connections = []; // Store all ESP32 SSE connections

// API endpoint to receive data from ESP32
app.post('/api/data', (req, res) => {
    const { type, status, data } = req.body;
    
    console.log(`[${new Date().toLocaleString()}] Received type: ${type}`);
    
    // Handle COMPLETE_DEVICE_DATA separately
    if (type === "COMPLETE_DEVICE_DATA") {
        // Store complete device scan
        const scanEntry = {
            id: Date.now(),
            type: type,
            data: data || "No data",
            rawData: req.body, // Store entire payload
            timestamp: new Date().toISOString(),
            formattedTime: new Date().toLocaleString(),
            deviceCount: data ? (data.split("|||").length - 1) : 0
        };
        
        deviceScans.unshift(scanEntry);
        
        // Limit device scans
        if (deviceScans.length > 100) {
            deviceScans = deviceScans.slice(0, 100);
        }
        
        console.log(`[${scanEntry.formattedTime}] COMPLETE_DEVICE_DATA: ${scanEntry.deviceCount} devices found`);
        
        // Send summary to dashboard
        const summaryEntry = {
            id: Date.now(),
            type: 'DEVICE_SCAN_COMPLETE',
            status: `Complete device scan received with ${scanEntry.deviceCount} devices`,
            timestamp: new Date().toISOString(),
            formattedTime: new Date().toLocaleString()
        };
        
        logs.unshift(summaryEntry);
        
        // Send to all connected web clients
        connectedClients.forEach(client => {
            client.write(`data: ${JSON.stringify(summaryEntry)}\n\n`);
        });
        
        // Also send the full data to clients who want it
        connectedClients.forEach(client => {
            client.write(`data: ${JSON.stringify({
                type: 'FULL_DEVICE_DATA',
                scanId: scanEntry.id,
                deviceCount: scanEntry.deviceCount,
                timestamp: scanEntry.timestamp
            })}\n\n`);
        });
        
        res.status(200).json({ 
            success: true, 
            message: 'Complete device data received',
            deviceCount: scanEntry.deviceCount 
        });
        return;
    }
    
    // Handle regular logs
    const logEntry = {
        id: Date.now(),
        type: type || 'UNKNOWN',
        status: status || 'No message',
        timestamp: new Date().toISOString(),
        formattedTime: new Date().toLocaleString()
    };
    
    logs.unshift(logEntry);
    
    if (logs.length > 1000) {
        logs = logs.slice(0, 1000);
    }
    
    console.log(`[${logEntry.formattedTime}] ${type}: ${status}`);
    
    // Send to all connected web clients
    connectedClients.forEach(client => {
        client.write(`data: ${JSON.stringify(logEntry)}\n\n`);
    });
    
    res.status(200).json({ success: true, message: 'Data received' });
});

// ESP32 connects here to listen for CHECK_NOW commands
app.get('/api/esp32/commands', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    
    // Send initial connection message
    res.write(`data: ${JSON.stringify({ command: 'CONNECTED', timestamp: Date.now() })}\n\n`);
    
    // Add this ESP32 to connections list
    esp32Connections.push(res);
    
    console.log(`✅ ESP32 connected to command stream. Total ESP32s: ${esp32Connections.length}`);
    
    // Log to dashboard
    const logEntry = {
        id: Date.now(),
        type: 'ESP32_CONNECTED',
        status: `ESP32 connected to command stream`,
        timestamp: new Date().toISOString(),
        formattedTime: new Date().toLocaleString()
    };
    logs.unshift(logEntry);
    connectedClients.forEach(client => {
        client.write(`data: ${JSON.stringify(logEntry)}\n\n`);
    });
    
    // Remove ESP32 when connection closes
    req.on('close', () => {
        esp32Connections = esp32Connections.filter(client => client !== res);
        console.log(`❌ ESP32 disconnected. Remaining: ${esp32Connections.length}`);
        
        const disconnectLog = {
            id: Date.now(),
            type: 'ESP32_DISCONNECTED',
            status: `ESP32 disconnected from command stream`,
            timestamp: new Date().toISOString(),
            formattedTime: new Date().toLocaleString()
        };
        logs.unshift(disconnectLog);
        connectedClients.forEach(client => {
            client.write(`data: ${JSON.stringify(disconnectLog)}\n\n`);
        });
    });
});

// Get complete device scan data
app.get('/api/device-scans', (req, res) => {
    res.json(deviceScans);
});

// Get specific device scan by ID
app.get('/api/device-scan/:id', (req, res) => {
    const scan = deviceScans.find(s => s.id == req.params.id);
    if (scan) {
        res.json(scan);
    } else {
        res.status(404).json({ error: 'Scan not found' });
    }
});

// Get latest device scan
app.get('/api/device-scans/latest', (req, res) => {
    if (deviceScans.length > 0) {
        res.json(deviceScans[0]);
    } else {
        res.json({ message: 'No scans available' });
    }
});

// Clear device scans
app.delete('/api/device-scans', (req, res) => {
    deviceScans = [];
    res.json({ success: true, message: 'Device scans cleared' });
});

// Trigger CHECK_NOW command to ALL connected ESP32 devices
app.post('/api/check-now', (req, res) => {
    const checkCommand = {
        command: 'CHECK_NOW',
        timestamp: Date.now(),
        reason: req.body.reason || 'Manual trigger from dashboard'
    };
    
    if (esp32Connections.length === 0) {
        return res.status(503).json({ 
            success: false, 
            message: 'No ESP32 devices connected to command stream' 
        });
    }
    
    // Send CHECK_NOW to all connected ESP32s
    let sentCount = 0;
    esp32Connections.forEach(esp32Client => {
        try {
            esp32Client.write(`data: ${JSON.stringify(checkCommand)}\n\n`);
            sentCount++;
        } catch (error) {
            console.error('Error sending to ESP32:', error);
        }
    });
    
    console.log(`🔍 CHECK_NOW sent to ${sentCount} ESP32 device(s)`);
    
    // Log the command
    const logEntry = {
        id: Date.now(),
        type: 'CHECK_NOW_SENT',
        status: `CHECK_NOW command sent to ${sentCount} ESP32 device(s)`,
        timestamp: new Date().toISOString(),
        formattedTime: new Date().toLocaleString()
    };
    
    logs.unshift(logEntry);
    
    // Notify dashboard
    connectedClients.forEach(client => {
        client.write(`data: ${JSON.stringify(logEntry)}\n\n`);
    });
    
    res.json({ 
        success: true, 
        message: `CHECK_NOW sent to ${sentCount} ESP32 device(s)`,
        deviceCount: sentCount
    });
});

// Get all logs
app.get('/api/logs', (req, res) => {
    res.json(logs);
});

// Clear all logs
app.delete('/api/logs', (req, res) => {
    logs = [];
    res.json({ success: true, message: 'Logs cleared' });
});

// Server-Sent Events for web dashboard
app.get('/api/stream', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    
    connectedClients.push(res);
    
    res.write(`data: ${JSON.stringify({ 
        type: 'CONNECTED', 
        status: 'Dashboard connected',
        timestamp: Date.now()
    })}\n\n`);
    
    req.on('close', () => {
        connectedClients = connectedClients.filter(client => client !== res);
    });
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'online', 
        totalLogs: logs.length,
        totalDeviceScans: deviceScans.length,
        connectedDashboards: connectedClients.length,
        connectedESP32s: esp32Connections.length,
        latestScan: deviceScans.length > 0 ? {
            timestamp: deviceScans[0].formattedTime,
            deviceCount: deviceScans[0].deviceCount
        } : null
    });
});

// Get ESP32 connection status
app.get('/api/esp32/status', (req, res) => {
    res.json({
        connected: esp32Connections.length > 0,
        deviceCount: esp32Connections.length
    });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log('\n╔══════════════════════════════════════════════════════════════╗');
    console.log('║     ESP32 Smart Lock Backend Server - COMPLETE DATA MODE    ║');
    console.log('╚══════════════════════════════════════════════════════════════╝\n');
    console.log(`✅ Server running on http://0.0.0.0:${PORT}`);
    console.log(`📡 ESP32 Command Stream: http://192.168.11.105:${PORT}/api/esp32/commands`);
    console.log(`📡 ESP32 Send Data: POST http://192.168.11.105:${PORT}/api/data`);
    console.log(`📊 Device Scans: GET http://192.168.11.105:${PORT}/api/device-scans`);
    console.log(`📊 Latest Scan: GET http://192.168.11.105:${PORT}/api/device-scans/latest`);
    console.log(`🌐 Dashboard: http://192.168.11.105:${PORT}`);
    console.log(`🔍 Trigger CHECK_NOW: POST http://192.168.11.105:${PORT}/api/check-now`);
    console.log('\n');
});