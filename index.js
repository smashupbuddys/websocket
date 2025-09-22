const WebSocket = require('ws');
const axios = require('axios');
const xml2js = require('xml2js');
const fs = require('fs');
const path = require('path');

function loadConfig() {
  try {
    const configPath = path.join(__dirname, 'config.json');
    const configData = fs.readFileSync(configPath, 'utf8');
    const config = JSON.parse(configData);
    
    config.server.port = process.env.PORT || config.server.port;
    config.n8n.webhookUrl = process.env.N8N_WEBHOOK_URL || config.n8n.webhookUrl;
    
    return config;
  } catch (error) {
    console.error('Error loading config:', error.message);
    console.log('Using default configuration...');
    return {
      server: { port: 8001, host: '0.0.0.0' },
      n8n: { webhookUrl: 'http://localhost:5678/webhook/biometric', timeout: 5000, retries: 3 },
      logging: { level: 'info', enableConsole: true },
      devices: { autoRespond: true, forwardKeepAlive: false },
      security: { allowedIPs: [], requireAuth: false },
      conversion: { customEventMapping: {
        'TimeLog_v2': 'attendance',
        'Registration': 'registration', 
        'Login': 'login',
        'KeepAlive': 'keepalive'
      }}
    };
  }
}

const config = loadConfig();
const PORT = config.server.port;
const N8N_WEBHOOK_URL = config.n8n.webhookUrl;

const xmlParser = new xml2js.Parser({ explicitArray: false });
const xmlBuilder = new xml2js.Builder({ rootName: 'Response', headless: true });

// Track last response time per connection
const connectionResponseTimes = new Map();

const wss = new WebSocket.Server({ port: PORT });

logMessage('info', `WebSocket server listening on ${config.server.host}:${PORT}`);
logMessage('info', `N8N webhook URL: ${N8N_WEBHOOK_URL}`);
logMessage('info', `Configuration loaded successfully`);
if (config.server.subdomain) {
  logMessage('info', `Subdomain configured: ${config.server.subdomain}`);
}

function convertXmlToJson(xmlData) {
  return new Promise((resolve, reject) => {
    xmlParser.parseString(xmlData, (err, result) => {
      if (err) {
        reject(err);
        return;
      }

      // Check if this is a Response message (our own server response)
      if (result.Response) {
        logMessage('debug', 'Ignoring server response message');
        resolve(null);
        return;
      }

      const message = result.Message;
      if (!message) {
        resolve(null);
        return;
      }

      // Determine the event type from either Event or Request field
      const eventKey = message.Event || message.Request || 'unknown';
      
      const jsonData = {
        event: getEventType(eventKey),
        deviceId: message.DeviceSerialNo || 'unknown',
        userId: message.UserID || null,
        timestamp: message.Time || new Date().toISOString(),
        action: message.Action || null,
        rawEvent: eventKey
      };
      
      if (config.conversion.includeRawXml) {
        jsonData.rawXml = xmlData;
      }

      resolve(jsonData);
    });
  });
}

function getEventType(event) {
  return config.conversion.customEventMapping[event] || 'unknown';
}

function convertToBeautifulJson(xmlData, deviceIP, connectionId) {
  return new Promise((resolve, reject) => {
    xmlParser.parseString(xmlData, (err, result) => {
      if (err) {
        resolve({
          success: false,
          error: "XML parsing failed",
          errorMessage: err.message,
          rawXml: xmlData,
          deviceIP: deviceIP,
          connectionId: connectionId,
          timestamp: new Date().toISOString()
        });
        return;
      }

      // Check if this is a Response message (ignore)
      if (result.Response) {
        resolve(null);
        return;
      }

      const timestamp = new Date().toISOString();
      let beautifulJson = {
        success: true,
        timestamp: timestamp,
        deviceIP: deviceIP,
        connectionId: connectionId,
        messageLength: xmlData.length
      };

      if (result.Message) {
        const msg = result.Message;
        const eventKey = msg.Event || msg.Request || 'unknown';
        const eventType = getEventType(eventKey);

        // Base message info
        beautifulJson.messageType = eventType;
        beautifulJson.rawEventType = eventKey;
        beautifulJson.deviceInfo = {
          serialNumber: msg.DeviceSerialNo || 'unknown',
          terminalType: msg.TerminalType || null,
          productName: msg.ProductName || null,
          cloudId: msg.CloudId || null
        };

        // Event-specific data formatting
        if (eventType === 'registration') {
          beautifulJson.eventData = {
            type: 'device_registration',
            device: {
              serialNumber: msg.DeviceSerialNo,
              terminalType: msg.TerminalType,
              productName: msg.ProductName,
              cloudId: msg.CloudId
            },
            requestType: msg.Request,
            registeredAt: timestamp
          };
        }
        
        else if (eventType === 'attendance') {
          beautifulJson.eventData = {
            type: 'time_log',
            employee: {
              userId: msg.UserID,
              action: msg.Action,
              verifyMode: msg.VerifyMode || null,
              workCode: msg.WorkCode || null
            },
            timing: {
              eventTime: msg.Time || timestamp,
              processedTime: timestamp
            },
            device: {
              serialNumber: msg.DeviceSerialNo
            }
          };
        }
        
        else if (eventType === 'login') {
          beautifulJson.eventData = {
            type: 'device_login',
            session: {
              userId: msg.UserID || null,
              loginTime: msg.Time || timestamp,
              device: {
                serialNumber: msg.DeviceSerialNo
              }
            }
          };
        }
        
        else if (eventType === 'keepalive') {
          beautifulJson.eventData = {
            type: 'heartbeat',
            device: {
              serialNumber: msg.DeviceSerialNo,
              lastSeen: msg.Time || timestamp
            },
            status: 'online'
          };
        }
        
        else {
          // Unknown event - include all data in a structured way
          beautifulJson.eventData = {
            type: 'unknown_event',
            rawData: msg,
            allFields: Object.keys(msg)
          };
        }

        // Always include metadata
        beautifulJson.metadata = {
          originalEvent: eventKey,
          processedAt: timestamp,
          xmlLength: xmlData.length,
          hasUserData: !!(msg.UserID),
          hasTimeData: !!(msg.Time)
        };

      } else {
        // Not a Message format
        beautifulJson.messageType = 'other';
        beautifulJson.eventData = {
          type: 'unknown_format',
          rawData: result
        };
      }

      resolve(beautifulJson);
    });
  });
}

function isAllowedIP(clientIp) {
  if (!config.security.allowedIPs || config.security.allowedIPs.length === 0) {
    return true;
  }
  
  const normalizedIp = clientIp.replace(/^::ffff:/, '');
  
  return config.security.allowedIPs.some(allowedRange => {
    if (allowedRange.includes('/')) {
      return isIpInRange(normalizedIp, allowedRange);
    }
    return normalizedIp === allowedRange;
  });
}

function isIpInRange(ip, range) {
  const [rangeIp, prefixLength] = range.split('/');
  const ipParts = ip.split('.').map(Number);
  const rangeIpParts = rangeIp.split('.').map(Number);
  const prefix = parseInt(prefixLength);
  
  const ipInt = (ipParts[0] << 24) + (ipParts[1] << 16) + (ipParts[2] << 8) + ipParts[3];
  const rangeInt = (rangeIpParts[0] << 24) + (rangeIpParts[1] << 16) + (rangeIpParts[2] << 8) + rangeIpParts[3];
  const mask = (-1 << (32 - prefix)) >>> 0;
  
  return (ipInt & mask) === (rangeInt & mask);
}

function logMessage(level, message, data = null) {
  if (!config.logging.enableConsole) return;
  
  const timestamp = new Date().toISOString();
  const logEntry = data ? `[${timestamp}] ${level.toUpperCase()}: ${message} ${JSON.stringify(data)}` : `[${timestamp}] ${level.toUpperCase()}: ${message}`;
  
  console.log(logEntry);
}

function createXmlResponse(event, status = 'OK') {
  const response = {
    Event: event,
    Status: status,
    Timestamp: new Date().toISOString()
  };
  return xmlBuilder.buildObject(response);
}

function createProtocolResponse(beautifulJson) {
  const deviceSerial = beautifulJson.deviceInfo?.serialNumber || 'unknown';
  const eventType = beautifulJson.rawEventType;
  const timestamp = new Date().toISOString();
  
  let response = {};
  
  // Build response based on event type following protocol
  if (eventType === 'Register') {
    // Generate a token for the device (in production, store this)
    const token = generateDeviceToken(deviceSerial);
    response = {
      Message: {
        Response: 'Register',
        DeviceSerialNo: deviceSerial,
        Token: token,
        Result: 'OK'
      }
    };
  } 
  else if (eventType === 'Login') {
    response = {
      Message: {
        Response: 'Login',
        DeviceSerialNo: deviceSerial,
        Result: 'OK'
      }
    };
  }
  else if (eventType === 'KeepAlive') {
    const deviceTime = beautifulJson.eventData?.device?.lastSeen || timestamp;
    response = {
      Message: {
        Response: 'KeepAlive',
        Result: 'OK',
        DevTime: deviceTime,
        ServerTime: timestamp
      }
    };
  }
  else if (eventType === 'TimeLog_v2') {
    // Extract TransID if available, or generate one
    const transId = extractTransId(beautifulJson) || generateTransId();
    response = {
      Message: {
        Response: 'TimeLog_v2',
        TransID: transId,
        Result: 'OK'
      }
    };
  }
  else if (eventType === 'AdminLog_v2') {
    const transId = extractTransId(beautifulJson) || generateTransId();
    response = {
      Message: {
        Response: 'AdminLog_v2',
        TransID: transId,
        Result: 'OK'
      }
    };
  }
  else {
    // Generic response for unknown events
    response = {
      Message: {
        Response: eventType,
        Result: 'OK',
        ServerTime: timestamp
      }
    };
  }
  
  const xmlBuilder = new xml2js.Builder({ 
    rootName: null, 
    headless: true,
    renderOpts: { pretty: false }
  });
  
  return xmlBuilder.buildObject(response);
}

function generateDeviceToken(deviceSerial) {
  // Generate a UUID-like token for the device
  return `${deviceSerial}-${Date.now()}-${Math.random().toString(36).substr(2, 8)}`;
}

function generateTransId() {
  return Math.random().toString(36).substr(2, 9);
}

function extractTransId(beautifulJson) {
  // Try to extract TransID from raw XML if available
  if (beautifulJson.rawXml && beautifulJson.rawXml.includes('<TransID>')) {
    const match = beautifulJson.rawXml.match(/<TransID>(.*?)<\/TransID>/);
    return match ? match[1] : null;
  }
  return null;
}

async function forwardToN8n(data) {
  let retries = 0;
  
  while (retries <= config.n8n.retries) {
    try {
      const headers = {
        'Content-Type': 'application/json'
      };
      
      if (config.security.requireAuth && config.security.authToken) {
        headers['Authorization'] = `Bearer ${config.security.authToken}`;
      }
      
      const response = await axios.post(N8N_WEBHOOK_URL, data, {
        headers,
        timeout: config.n8n.timeout
      });
      
      logMessage('info', '✓ Forwarded to n8n:', data);
      return true;
    } catch (error) {
      retries++;
      logMessage('error', `✗ Failed to forward to n8n (attempt ${retries}/${config.n8n.retries + 1}):`, error.message);
      
      if (retries <= config.n8n.retries) {
        await new Promise(resolve => setTimeout(resolve, config.n8n.retryDelay));
      }
    }
  }
  
  return false;
}

wss.on('connection', (ws, req) => {
  const clientIp = req.socket.remoteAddress;
  
  if (!isAllowedIP(clientIp)) {
    logMessage('warn', `Connection rejected from unauthorized IP: ${clientIp}`);
    ws.close(1008, 'Unauthorized IP');
    return;
  }
  
  logMessage('info', `New connection from ${clientIp}`);

  ws.on('message', async (data) => {
    try {
      const xmlData = data.toString();
      logMessage('info', `Received raw XML:`, xmlData);

      // Convert XML to beautiful JSON format
      const connectionId = `${clientIp}-${Date.now()}`;
      const beautifulJson = await convertToBeautifulJson(xmlData, clientIp, connectionId);
      
      // If it's null, it means it's a server response - ignore it
      if (!beautifulJson) {
        logMessage('debug', 'Ignoring server response message');
        return;
      }

      // Log the beautiful conversion
      if (beautifulJson.success) {
        logMessage('info', `Converted to beautiful JSON:`, {
          messageType: beautifulJson.messageType,
          deviceId: beautifulJson.deviceInfo?.serialNumber,
          eventType: beautifulJson.eventData?.type
        });
      } else {
        logMessage('warn', 'XML conversion failed:', beautifulJson.error);
      }

      // Forward beautiful JSON to n8n (only if successful conversion or errors)
      await forwardToN8n(beautifulJson);

      // Send throttled acknowledgment ONLY for real device messages
      if (config.devices.autoRespond && beautifulJson.success) {
        const now = Date.now();
        const lastResponseTime = connectionResponseTimes.get(clientIp) || 0;
        const timeSinceLastResponse = now - lastResponseTime;
        
        let shouldRespond = false;
        
        // Always respond to important events
        const eventType = beautifulJson.rawEventType || '';
        if (config.devices.alwaysRespondToEvents.includes(eventType)) {
          shouldRespond = true;
          logMessage('debug', `Responding to important event: ${eventType}`);
        }
        // Or respond if enough time has passed (throttle)
        else if (timeSinceLastResponse >= config.devices.responseThrottleMs) {
          shouldRespond = true;
          logMessage('debug', `Responding after throttle interval (${timeSinceLastResponse}ms)`);
        }
        
        if (shouldRespond) {
          const protocolResponse = createProtocolResponse(beautifulJson);
          ws.send(protocolResponse);
          connectionResponseTimes.set(clientIp, now);
          logMessage('debug', `Sent protocol response to ${clientIp} for ${eventType}`);
        } else {
          logMessage('debug', `Throttled response (last: ${timeSinceLastResponse}ms ago)`);
        }
      }

    } catch (error) {
      logMessage('error', 'Error processing message:', error.message);
      if (config.devices.autoRespond) {
        ws.send(createXmlResponse('Error', 'Processing failed'));
      }
    }
  });

  ws.on('close', () => {
    logMessage('info', `Connection closed from ${clientIp}`);
    // Clean up response tracking for this connection
    connectionResponseTimes.delete(clientIp);
  });

  ws.on('error', (error) => {
    logMessage('error', `WebSocket error from ${clientIp}:`, error.message);
    // Clean up response tracking for this connection
    connectionResponseTimes.delete(clientIp);
  });

  if (config.devices.autoRespond) {
    const now = Date.now();
    connectionResponseTimes.set(clientIp, now);
    // Send a simple welcome - device will send Register request next
    const welcomeResponse = createXmlResponse('Welcome', 'Connected');
    ws.send(welcomeResponse);
    logMessage('debug', `Sent welcome message to ${clientIp}`);
  }
});

wss.on('error', (error) => {
  logMessage('error', 'WebSocket server error:', error.message);
});

process.on('SIGTERM', () => {
  logMessage('info', 'Received SIGTERM, closing server...');
  wss.close(() => {
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  logMessage('info', 'Received SIGINT, closing server...');
  wss.close(() => {
    process.exit(0);
  });
});