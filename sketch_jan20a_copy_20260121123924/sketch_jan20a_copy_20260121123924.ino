#define CONFIG_ARDUHAL_LOG_DEFAULT_LEVEL_NONE

#include <WiFi.h>
#include <HTTPClient.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>

// WiFi credentials
const char* ssid = "Malware";
const char* password = "Raktim01@";
const char* serverUrl = "http://192.168.11.105:3000/api/data";
const char* commandStreamUrl = "http://192.168.11.105:3000/api/esp32/commands";

// BLE Configuration
#define SERVICE_UUID "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
#define SCAN_TIME 5  // Scan for 5 seconds when CHECK_NOW received

// Status LED Pin
#define STATUS_LED 2

// BLE Scanner
BLEScan* pBLEScan;
bool scanComplete = false;
String foundUserToken = "";
String foundDeviceName = "";
int foundDeviceRSSI = 0;
String allDevicesData = "";  // To store all found devices data

// HTTP Stream
HTTPClient httpStream;
WiFiClient client;
bool streamConnected = false;
unsigned long lastHeartbeat = 0;
unsigned long lastReconnect = 0;

// Function to send logs to backend
void sendLog(String type, String message) {
    if(WiFi.status() == WL_CONNECTED) {
        HTTPClient http;
        http.setTimeout(5000);
        http.begin(serverUrl);
        http.addHeader("Content-Type", "application/json");
        
        String json = "{\"type\":\"" + type + "\", \"status\":\"" + message + "\"}";
        int httpCode = http.POST(json);
        
        if (httpCode > 0) {
            Serial.printf("[HTTP] ✅ Sent to backend\n");
        } else {
            Serial.printf("[HTTP] ❌ Failed: %s\n", http.errorToString(httpCode).c_str());
        }
        http.end();
    }
    Serial.printf("[%s] %s\n", type.c_str(), message.c_str());
}

// Function to send complete device data to backend
void sendCompleteDeviceData(String deviceData) {
    if(WiFi.status() == WL_CONNECTED) {
        HTTPClient http;
        http.setTimeout(10000);  // Increase timeout for large data
        http.begin(serverUrl);
        http.addHeader("Content-Type", "application/json");
        
        // Escape JSON characters
        deviceData.replace("\\", "\\\\");
        deviceData.replace("\"", "\\\"");
        deviceData.replace("\n", "\\n");
        deviceData.replace("\r", "\\r");
        
        String json = "{\"type\":\"COMPLETE_DEVICE_DATA\", \"data\":\"" + deviceData + "\"}";
        int httpCode = http.POST(json);
        
        if (httpCode > 0) {
            Serial.printf("[HTTP] ✅ Complete device data sent (Code: %d)\n", httpCode);
        } else {
            Serial.printf("[HTTP] ❌ Failed to send complete device data: %s\n", http.errorToString(httpCode).c_str());
        }
        http.end();
    }
}

// Function to extract and format MAC address
String getMacAddress(BLEAddress address) {
    String mac = address.toString().c_str();
    mac.toUpperCase();
    return mac;
}

// Function to convert bytes to hex string
String bytesToHexString(const uint8_t* data, size_t length) {
    String hexString = "";
    for(size_t i = 0; i < length; i++) {
        char hex[3];
        sprintf(hex, "%02X", data[i]);
        hexString += hex;
        if(i < length - 1) hexString += " ";
    }
    return hexString;
}

// Function to analyze manufacturer data

String analyzeManufacturerData(String mfgDataStr) {
    String analysis = "";
    
    if(mfgDataStr.length() == 0) {
        return "Empty";
    }
    
    analysis += "Length: " + String(mfgDataStr.length()) + " bytes | ";
    
    // Check for iBeacon (Apple: 0x004C)
    if(mfgDataStr.length() >= 4) {
        uint8_t mfgId1 = mfgDataStr[0];
        uint8_t mfgId2 = mfgDataStr[1];
        uint16_t manufacturerId = (mfgId2 << 8) | mfgId1;
        
        analysis += "MFG ID: 0x" + String(manufacturerId, HEX) + " | ";
        
        if(manufacturerId == 0x004C) { // Apple
            analysis += "Apple ";
            if(mfgDataStr.length() >= 25) {
                uint8_t beaconType = mfgDataStr[2];
                uint8_t dataLength = mfgDataStr[3];
                
                if(beaconType == 0x02 && dataLength == 0x15) {
                    analysis += "iBeacon | ";
                    
                    // Extract UUID - FIXED FORMATTING
                    String uuid = "";
                    for(int i = 4; i < 20; i++) {
                        char hex[3];
                        sprintf(hex, "%02X", (uint8_t)mfgDataStr[i]);
                        uuid += hex;
                    }
                    
                    // Format UUID correctly: 8-4-4-4-12
                    String formattedUUID = "";
                    formattedUUID += uuid.substring(0, 8);
                    formattedUUID += "-";
                    formattedUUID += uuid.substring(8, 12);
                    formattedUUID += "-";
                    formattedUUID += uuid.substring(12, 16);
                    formattedUUID += "-";
                    formattedUUID += uuid.substring(16, 20);
                    formattedUUID += "-";
                    formattedUUID += uuid.substring(20, 32);
                    
                    analysis += "UUID: " + formattedUUID + " | ";
                    
                    // Check if it's our target
                    if(formattedUUID.equalsIgnoreCase("4FAFC201-1FB5-459E-8FCC-C5C9C331914B")) {
                        analysis += "✅ TARGET BEACON | ";
                    }
                    
                    // Major and Minor
                    uint16_t major = (mfgDataStr[20] << 8) | mfgDataStr[21];
                    uint16_t minor = (mfgDataStr[22] << 8) | mfgDataStr[23];
                    int8_t txPower = mfgDataStr[24];
                    
                    analysis += "Major: " + String(major) + " | ";
                    analysis += "Minor: " + String(minor) + " | ";
                    analysis += "TX: " + String(txPower) + "dBm";
                    
                    // Store if it's our target
                    if(formattedUUID.equalsIgnoreCase("4FAFC201-1FB5-459E-8FCC-C5C9C331914B")) {
                        foundUserToken = String(major) + "-" + String(minor);
                    }
                }
            }
        } else if(manufacturerId == 0x0059) { // Nordic
            analysis += "Nordic Semiconductor";
        } else if(manufacturerId == 0x006C) { // Samsung
            analysis += "Samsung";
        } else if(manufacturerId == 0x00E0) { // Google
            analysis += "Google";
        } else {
            analysis += "Unknown Manufacturer";
        }
    }
    
    return analysis;
}
// Function to get device type from name and services
String getDeviceType(String name, bool hasServiceUUID) {
    String type = "Unknown";
    
    name.toLowerCase();
    
    if(name.indexOf("iphone") >= 0 || name.indexOf("ipad") >= 0) {
        type = "Apple Device";
    } else if(name.indexOf("samsung") >= 0 || name.indexOf("galaxy") >= 0) {
        type = "Samsung Device";
    } else if(name.indexOf("watch") >= 0) {
        type = "Smart Watch";
    } else if(name.indexOf("fitbit") >= 0 || name.indexOf("mi band") >= 0) {
        type = "Fitness Tracker";
    } else if(name.indexOf("headphones") >= 0 || name.indexOf("buds") >= 0 || name.indexOf("ear") >= 0) {
        type = "Audio Device";
    } else if(name.indexOf("ibeacon") >= 0 || name.indexOf("beacon") >= 0) {
        type = "BLE Beacon";
    } else if(hasServiceUUID) {
        type = "BLE Device with Services";
    } else if(name.length() == 0) {
        type = "Anonymous Device";
    }
    
    return type;
}

// BLE Scan callback - Called for each discovered device
class MyAdvertisedDeviceCallbacks: public BLEAdvertisedDeviceCallbacks {
    void onResult(BLEAdvertisedDevice advertisedDevice) {
        String deviceDetails = "\n════════════════════════════════════════════════\n";
        
        // Basic Information
        deviceDetails += "🔍 **DEVICE DETAILS**\n";
        deviceDetails += "════════════════════════════════════════════════\n";
        
        // Device Name
        String deviceName = advertisedDevice.getName().c_str();
        if(deviceName.length() > 0) {
            deviceDetails += "📛 Name: " + deviceName + "\n";
        } else {
            deviceName = "Unknown";
            deviceDetails += "📛 Name: [UNKNOWN/ANONYMOUS]\n";
        }
        
        // MAC Address
        String macAddress = getMacAddress(advertisedDevice.getAddress());
        deviceDetails += "📍 MAC: " + macAddress + "\n";
        
        // RSSI and Signal Strength
        int rssi = advertisedDevice.getRSSI();
        deviceDetails += "📶 RSSI: " + String(rssi) + " dBm\n";
        
        // Estimate distance (very rough)
        String distance = "Unknown";
        if(rssi > -50) distance = "Very Close (<1m)";
        else if(rssi > -60) distance = "Close (~1-2m)";
        else if(rssi > -70) distance = "Medium (~2-5m)";
        else if(rssi > -80) distance = "Far (~5-10m)";
        else distance = "Very Far (>10m)";
        deviceDetails += "📏 Estimated Distance: " + distance + "\n";
        
        // Device Type Analysis
        bool hasServices = advertisedDevice.haveServiceUUID();
        String deviceType = getDeviceType(deviceName, hasServices);
        deviceDetails += "📱 Device Type: " + deviceType + "\n";
        
        // Service UUIDs
        if(advertisedDevice.haveServiceUUID()) {
            deviceDetails += "\n🔗 **SERVICE UUIDs:**\n";
            BLEUUID serviceUUID = advertisedDevice.getServiceUUID();
            String uuidStr = serviceUUID.toString().c_str();
            deviceDetails += "   UUID: " + uuidStr + "\n";
            
            // Check if this is our target service
            if(uuidStr.equalsIgnoreCase(SERVICE_UUID)) {
                deviceDetails += "   ✅ **TARGET SERVICE FOUND!**\n";
                foundDeviceName = deviceName;
                foundDeviceRSSI = rssi;
            }
        } else {
            deviceDetails += "\n🔗 Service UUIDs: None advertised\n";
        }
        
        // Manufacturer Data
        if(advertisedDevice.haveManufacturerData()) {
            String mfgDataStr = advertisedDevice.getManufacturerData();
            deviceDetails += "\n🏭 **MANUFACTURER DATA:**\n";
            
            // Hex Dump
            deviceDetails += "   Hex: ";
            for(size_t i = 0; i < mfgDataStr.length(); i++) {
                char hex[3];
                sprintf(hex, "%02X", (uint8_t)mfgDataStr[i]);
                deviceDetails += hex;
                deviceDetails += " ";
            }
            deviceDetails += "\n";
            
            // ASCII View
            deviceDetails += "   ASCII: ";
            for(size_t i = 0; i < mfgDataStr.length(); i++) {
                char c = mfgDataStr[i];
                if(c >= 32 && c <= 126) {  // Printable ASCII
                    deviceDetails += c;
                } else {
                    deviceDetails += ".";
                }
            }
            deviceDetails += "\n";
            
            // Analysis - Using the corrected function
            String analysis = analyzeManufacturerData(mfgDataStr);
            deviceDetails += "   Analysis: " + analysis + "\n";
            
            // Also check if this is an iBeacon with our target UUID
            if(mfgDataStr.length() >= 25) {
                uint8_t mfgId1 = mfgDataStr[0];
                uint8_t mfgId2 = mfgDataStr[1];
                uint8_t beaconType = mfgDataStr[2];
                uint8_t dataLength = mfgDataStr[3];
                
                if(mfgId1 == 0x4C && mfgId2 == 0x00 && 
                   beaconType == 0x02 && dataLength == 0x15) {
                    
                    // Extract and format UUID
                    String uuidHex = "";
                    for(int i = 4; i < 20; i++) {
                        char hex[3];
                        sprintf(hex, "%02X", (uint8_t)mfgDataStr[i]);
                        uuidHex += hex;
                    }
                    
                    // Format UUID correctly
                    String formattedUUID = "";
                    formattedUUID += uuidHex.substring(0, 8);
                    formattedUUID += "-";
                    formattedUUID += uuidHex.substring(8, 12);
                    formattedUUID += "-";
                    formattedUUID += uuidHex.substring(12, 16);
                    formattedUUID += "-";
                    formattedUUID += uuidHex.substring(16, 20);
                    formattedUUID += "-";
                    formattedUUID += uuidHex.substring(20, 32);
                    
                    // Check if it's our target
                    if(formattedUUID.equalsIgnoreCase("4FAFC201-1FB5-459E-8FCC-C5C9C331914B")) {
                        deviceDetails += "\n✨ **iBeacon with TARGET UUID DETECTED!** ✨\n";
                        
                        // Extract Major and Minor
                        uint16_t major = (mfgDataStr[20] << 8) | mfgDataStr[21];
                        uint16_t minor = (mfgDataStr[22] << 8) | mfgDataStr[23];
                        
                        foundUserToken = String(major) + "-" + String(minor);
                        foundDeviceName = deviceName;
                        foundDeviceRSSI = rssi;
                        scanComplete = true;
                    }
                }
            }
        } else {
            deviceDetails += "\n🏭 Manufacturer Data: None\n";
        }
        
        // TX Power
        if(advertisedDevice.haveTXPower()) {
            int8_t txPower = advertisedDevice.getTXPower();
            deviceDetails += "\n📡 TX Power: " + String(txPower) + " dBm\n";
        }
        
        // Appearance
        deviceDetails += "\n🎨 Appearance: ";
        if(advertisedDevice.haveAppearance()) {
            deviceDetails += String(advertisedDevice.getAppearance());
        } else {
            deviceDetails += "Not specified";
        }
        deviceDetails += "\n";
        
        // Check if this device is advertising our target UUID as a service
        if(advertisedDevice.haveServiceUUID()) {
            BLEUUID serviceUUID = advertisedDevice.getServiceUUID();
            String uuidStr = serviceUUID.toString().c_str();
            
            if(uuidStr.equalsIgnoreCase(SERVICE_UUID)) {
                deviceDetails += "\n✨ **TARGET SERVICE UUID DETECTED!** ✨\n";
            }
        }
        
        deviceDetails += "════════════════════════════════════════════════\n";
        
        // Add to serial output
        Serial.print(deviceDetails);
        
        // Add to global data string (without newlines for JSON)
        String cleanDetails = deviceDetails;
        cleanDetails.replace("\n", "\\n");
        cleanDetails.replace("\"", "'");
        allDevicesData += cleanDetails + "|||";
    }
};
// Scan for nearby BLE beacons
void scanForDevices() {
    Serial.println("\n╔════════════════════════════════════╗");
    Serial.println("║   🔍 SCANNING FOR DEVICES...       ║");
    Serial.println("╚════════════════════════════════════╝");
    
    // Flash LED during scan
    for(int i = 0; i < 3; i++) {
        digitalWrite(STATUS_LED, HIGH);
        delay(100);
        digitalWrite(STATUS_LED, LOW);
        delay(100);
    }
    
    // Reset found data
    foundUserToken = "";
    foundDeviceName = "";
    foundDeviceRSSI = 0;
    scanComplete = false;
    allDevicesData = "";
    
    // Configure scanner
    pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());
    pBLEScan->setActiveScan(true);
    pBLEScan->setInterval(100);
    pBLEScan->setWindow(99);
    
    // Start scan
    Serial.printf("Scanning for %d seconds...\n", SCAN_TIME);
    BLEScanResults* foundDevices = pBLEScan->start(SCAN_TIME, false);
    
    // Send complete scan summary to backend
    String scanSummary = "\n\n╔══════════════════════════════════════════════════════╗\n";
    scanSummary += "║                    SCAN COMPLETE                       ║\n";
    scanSummary += "╠══════════════════════════════════════════════════════╣\n";
    scanSummary += "║  Total Devices Found: " + String(foundDevices->getCount()) + "\n";
    scanSummary += "║  Scan Duration: " + String(SCAN_TIME) + " seconds\n";
    scanSummary += "║  Timestamp: " + String(millis()) + "ms\n";
    scanSummary += "╚══════════════════════════════════════════════════════╝\n";
    
    if(foundDevices->getCount() > 0) {
        // Send COMPLETE device data to backend
        sendCompleteDeviceData(allDevicesData);
        
        if(foundUserToken.length() > 0) {
            // Authorized device found
            String message = "✅ AUTHORIZED USER FOUND | ";
            message += "Device: " + foundDeviceName + " | ";
            message += "Token: " + foundUserToken + " | ";
            message += "RSSI: " + String(foundDeviceRSSI) + " dBm | ";
            message += "Distance: ~" + String(abs(foundDeviceRSSI / 10)) + "m | ";
            message += "Total Devices: " + String(foundDevices->getCount());
            
            sendLog("USER_DETECTED", message);
            
            // Flash LED for success
            for(int i = 0; i < 10; i++) {
                digitalWrite(STATUS_LED, HIGH);
                delay(50);
                digitalWrite(STATUS_LED, LOW);
                delay(50);
            }
            
            Serial.println("\n✅ USER AUTHORIZED - DOOR CAN UNLOCK");
        } else {
            // No authorized device found, but send full details
            String message = "❌ NO AUTHORIZED DEVICES FOUND | ";
            message += "Total Scanned: " + String(foundDevices->getCount()) + " devices | ";
            message += "Complete device data has been sent to backend";
            
            sendLog("NO_USER_FOUND", message);
            
            // Also send a summary
            sendLog("SCAN_SUMMARY", "Scan completed with " + String(foundDevices->getCount()) + " devices");
            
            Serial.println("\n❌ NO AUTHORIZED USER DETECTED");
            Serial.println("📊 Complete device data has been sent to backend");
        }
    } else {
        // No devices found at all
        String message = "📭 NO DEVICES FOUND | ";
        message += "Scan Duration: " + String(SCAN_TIME) + " seconds | ";
        message += "Check BLE scanner configuration";
        
        sendLog("NO_DEVICES_FOUND", message);
        Serial.println("\n📭 NO DEVICES DETECTED DURING SCAN");
    }
    
    // Clear scan results
    pBLEScan->clearResults();
}

// Rest of your code remains the same...
// Connect to backend command stream
void connectToCommandStream() {
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("❌ WiFi not connected");
        return;
    }
    
    Serial.println("📡 Connecting to command stream...");
    
    httpStream.begin(client, commandStreamUrl);
    httpStream.addHeader("Accept", "text/event-stream");
    httpStream.addHeader("Cache-Control", "no-cache");
    
    int httpCode = httpStream.GET();
    
    if (httpCode == HTTP_CODE_OK) {
        streamConnected = true;
        Serial.println("✅ Connected to command stream!");
        sendLog("SYSTEM", "Command stream connected");
    } else {
        streamConnected = false;
        Serial.printf("❌ Connection failed: %d\n", httpCode);
        httpStream.end();
    }
}

// Check for commands from backend
void checkForCommands() {
    if (!streamConnected) return;
    
    if (httpStream.connected()) {
        WiFiClient* stream = httpStream.getStreamPtr();
        
        while (stream->available()) {
            String line = stream->readStringUntil('\n');
            line.trim();
            
            if (line.startsWith("data:")) {
                String jsonData = line.substring(5);
                jsonData.trim();
                
                Serial.println("📥 Command: " + jsonData);
                
                // Check for CHECK_NOW command
                if (jsonData.indexOf("CHECK_NOW") > 0) {
                    handleCheckNow();
                }
            }
        }
    } else {
        Serial.println("⚠️ Stream disconnected, reconnecting...");
        streamConnected = false;
        httpStream.end();
        delay(2000);
        connectToCommandStream();
    }
}

// Handle CHECK_NOW command
void handleCheckNow() {
    Serial.println("\n╔════════════════════════════════════╗");
    Serial.println("║   🔍 CHECK_NOW RECEIVED            ║");
    Serial.println("║   SCANNING FOR NEARBY PHONES...    ║");
    Serial.println("╚════════════════════════════════════╝\n");
    
    sendLog("CHECK_NOW_RECEIVED", "Starting BLE scan for authorized devices...");
    
    // Scan for devices
    scanForDevices();
}

void setup() {
    Serial.begin(115200);
    delay(1000);
    
    pinMode(STATUS_LED, OUTPUT);
    digitalWrite(STATUS_LED, LOW);
    
    Serial.println("\n\n╔══════════════════════════════════════════════════════╗");
    Serial.println("║         ESP32-S3 Smart Lock System                    ║");
    Serial.println("║         COMPLETE BLE SCANNER MODE                     ║");
    Serial.println("╚══════════════════════════════════════════════════════╝\n");
    
    // WiFi Setup
    Serial.println("🌐 Connecting to WiFi...");
    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid, password);
    
    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 20) {
        delay(500);
        Serial.print(".");
        digitalWrite(STATUS_LED, !digitalRead(STATUS_LED));
        attempts++;
    }
    
    if (WiFi.status() == WL_CONNECTED) {
        Serial.println("\n✅ WiFi Connected!");
        Serial.print("📍 IP: ");
        Serial.println(WiFi.localIP());
        digitalWrite(STATUS_LED, HIGH);
        delay(1000);
        digitalWrite(STATUS_LED, LOW);
        sendLog("SYSTEM", "WiFi Connected - IP: " + WiFi.localIP().toString());
    } else {
        Serial.println("\n❌ WiFi Failed!");
    }
    
    // Initialize BLE Scanner
    Serial.println("\n📡 Initializing BLE Scanner...");
    BLEDevice::init("ESP32_SCANNER");
    pBLEScan = BLEDevice::getScan();
    pBLEScan->setActiveScan(true);
    Serial.println("✅ BLE Scanner Ready");
    sendLog("SYSTEM", "BLE Scanner initialized");
    
    // Connect to command stream
    delay(1000);
    connectToCommandStream();
    
    Serial.println("\n╔══════════════════════════════════════════════════════╗");
    Serial.println("║  ✅ SYSTEM READY                                      ║");
    Serial.println("║  Waiting for CHECK_NOW commands...                   ║");
    Serial.println("║  Will send COMPLETE device data to backend           ║");
    Serial.println("╚══════════════════════════════════════════════════════╝\n");
}

void loop() {
    // WiFi Reconnection
    if (WiFi.status() != WL_CONNECTED) {
        if (millis() - lastReconnect > 30000) {
            Serial.println("🔄 Reconnecting WiFi...");
            WiFi.reconnect();
            lastReconnect = millis();
        }
    }
    
    // Check for commands
    checkForCommands();
    
    // Heartbeat
    if (millis() - lastHeartbeat > 60000) {
        String status = "Alive | WiFi: " + String(WiFi.status() == WL_CONNECTED ? "ON" : "OFF");
        status += " | Stream: " + String(streamConnected ? "Connected" : "Disconnected");
        
        sendLog("HEARTBEAT", status);
        
        // Reconnect stream if needed
        if (WiFi.status() == WL_CONNECTED && !streamConnected) {
            connectToCommandStream();
        }
        
        lastHeartbeat = millis();
    }
    
    delay(10);
}