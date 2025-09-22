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

      const jsonData = {
        event: getEventType(message.Event),
        deviceId: message.DeviceSerialNo || 'unknown',
        userId: message.UserID || null,
        timestamp: message.Time || new Date().toISOString(),
        action: message.Action || null,
        rawEvent: message.Event
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

      // Create payload with raw XML and metadata
      const payload = {
        rawXml: xmlData,
        timestamp: new Date().toISOString(),
        deviceIP: clientIp,
        messageLength: xmlData.length,
        connectionId: `${clientIp}-${Date.now()}`,
        serverInfo: {
          port: config.server.port,
          subdomain: config.server.subdomain || null
        }
      };

      // Try to extract basic info for logging (optional)
      let shouldForward = true;
      try {
        const basicInfo = await convertXmlToJson(xmlData);
        if (basicInfo) {
          payload.parsedInfo = basicInfo;
          logMessage('info', `Parsed info:`, basicInfo);
        } else {
          // This means it's a Response message - don't forward
          shouldForward = false;
          logMessage('debug', 'Skipping forward of server response message');
        }
      } catch (parseError) {
        logMessage('debug', 'Could not parse XML, sending raw data anyway');
      }

      // Only forward actual device messages, not server responses
      if (shouldForward) {
        await forwardToN8n(payload);
      }

      // Send throttled acknowledgment ONLY for real device messages
      if (config.devices.autoRespond && shouldForward) {
        const now = Date.now();
        const lastResponseTime = connectionResponseTimes.get(clientIp) || 0;
        const timeSinceLastResponse = now - lastResponseTime;
        
        let shouldRespond = false;
        
        // Always respond to important events
        if (payload.parsedInfo) {
          const eventType = payload.parsedInfo.rawEvent || '';
          if (config.devices.alwaysRespondToEvents.includes(eventType)) {
            shouldRespond = true;
            logMessage('debug', `Responding to important event: ${eventType}`);
          }
          // Or respond if enough time has passed (throttle)
          else if (timeSinceLastResponse >= config.devices.responseThrottleMs) {
            shouldRespond = true;
            logMessage('debug', `Responding after throttle interval (${timeSinceLastResponse}ms)`);
          }
        }
        
        if (shouldRespond) {
          const xmlResponse = createXmlResponse('Received', 'OK');
          ws.send(xmlResponse);
          connectionResponseTimes.set(clientIp, now);
          logMessage('debug', `Sent acknowledgment to ${clientIp}`);
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
    ws.send(createXmlResponse('Welcome', 'Connected'));
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