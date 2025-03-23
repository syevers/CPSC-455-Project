import os from 'node:os';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { WebSocketServer, WebSocket } from 'ws';
import https from 'https';
import { fileURLToPath } from 'url';
import path from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 8080;
const options = {
  key: readFileSync('../certs/private.pem'),
  cert: readFileSync('../certs/public.pem'),
};

// Initialize accounts file if it doesn't exist
function initializeAccountsFile() {
  const accountsPath = path.join(__dirname, 'accounts.json');
  if (!existsSync(accountsPath)) {
    console.log('[SERVER] Creating new accounts.json file');
    const emptyAccounts = {
      users: [],
    };
    writeFileSync(accountsPath, JSON.stringify(emptyAccounts, null, 2), 'utf8');
    return emptyAccounts;
  }
  return null;
}

// Load accounts from JSON file
function loadAccounts() {
  const accountsPath = path.join(__dirname, 'accounts.json');

  try {
    // Try to initialize file if it doesn't exist
    const initialized = initializeAccountsFile();
    if (initialized) {
      return initialized;
    }

    // Read existing file
    const accountsData = readFileSync(accountsPath, 'utf8');
    const parsed = JSON.parse(accountsData);

    // Ensure the parsed data has a users array
    if (!parsed || !Array.isArray(parsed.users)) {
      console.error('[SERVER] Invalid accounts.json format. Resetting to empty.');
      const emptyAccounts = {
        users: [],
      };
      writeFileSync(accountsPath, JSON.stringify(emptyAccounts, null, 2), 'utf8');
      return emptyAccounts;
    }

    return parsed;
  }
  catch (error) {
    console.error('[SERVER] Error loading accounts:', error);
    // If there's an error, try to reset the file to a valid state
    try {
      const emptyAccounts = {
        users: [],
      };
      writeFileSync(accountsPath, JSON.stringify(emptyAccounts, null, 2), 'utf8');
      return emptyAccounts;
    }
    catch (writeError) {
      console.error('[SERVER] Failed to reset accounts.json:', writeError);
      return { users: [] };
    }
  }
}

function getLocalIPAddress() {
  const interfaces = os.networkInterfaces();
  for (const interfaceName in interfaces) {
    for (const iface of interfaces[interfaceName]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  // fallback to localhost (for now)
  return '127.0.0.1';
}

const serverAddress = getLocalIPAddress();
const server = https.createServer(options).listen(PORT, serverAddress, () => {
  console.log(`[SERVER] Running on wss:${serverAddress}:${PORT}`);
});

const wss = new WebSocketServer({ server });
const users = new Map<WebSocket, string>();
const heartbeatMap = new Map<WebSocket, NodeJS.Timeout>();
const messageTimestamps = new Map<WebSocket, number[]>();
const blockedUsers = new Map<WebSocket, number>();
const reconnectingClients = new Map<string, WebSocket>();
const aliveClients = new WeakMap<WebSocket, number>();

const RATE_LIMIT = 5;
const BLOCK_DURATION = 10000;
const HEARTBEAT_INTERVAL = 30000;
const RECONNECT_TIMEOUT = 30000;

console.log(`[SERVER] Listening for connections on port ${PORT}`);

// Function to validate user credentials
// Add new user to accounts.json
function addNewUser(username: string, password: string): boolean {
  try {
    const accounts = loadAccounts();

    // Check for duplicate username
    if (accounts.users.some((user: { username: string }) => user.username === username)) {
      console.log('[SERVER] Username already exists:', username);
      return false;
    }

    // Add new user
    accounts.users.push({ username, password });

    // Save updated accounts
    const accountsPath = path.join(__dirname, 'accounts.json');
    writeFileSync(accountsPath, JSON.stringify(accounts, null, 2), 'utf8');
    console.log('[SERVER] New user added:', username);
    return true;
  }
  catch (error) {
    console.error('[SERVER] Error adding new user:', error);
    return false;
  }
}

// Validate or create user account
function validateCredentials(username: string, password: string): boolean {
  const accounts = loadAccounts();

  // Additional safety check
  if (!accounts || !Array.isArray(accounts.users)) {
    console.error('[SERVER] Invalid accounts data structure');
    return false;
  }

  try {
    const user = accounts.users.find((u: { username: string; password: string }) =>
      u.username === username,
    );

    if (!user) {
      // User doesn't exist, create new account
      console.log('[SERVER] Creating new user account:', username);
      return addNewUser(username, password);
    }

    return user.password === password;
  }
  catch (error) {
    console.error('[SERVER] Error validating credentials:', error);
    return false;
  }
}

wss.on('connection', (ws, req) => {
  console.log('[SERVER] New client connected.');

  let username: string | undefined;

  if (req.headers['sec-websocket-protocol']) {
    username = req.headers['sec-websocket-protocol'];
    console.log(`[SERVER] ${username} reconnected.`);

    if (reconnectingClients.has(username)) {
      reconnectingClients.delete(username);
    }
  }

  ws.on('error', console.error);

  ws.on('message', (data) => {
    try {
      const parsedData = JSON.parse(data.toString());

      if (parsedData.type === 'pong') {
        aliveClients.set(ws, 0);
        return;
      }

      if (parsedData.type === 'logout') {
        const username = users.get(ws);
        if (username) {
          console.log(`[SERVER] ${username} has logged out.`);
          users.delete(ws);
          broadcast(`[SERVER]: ${username} has left the chat.`);
          sendUserList();
        }
        ws.close();
        return;
      }

      if (blockedUsers.has(ws)) {
        const remainingTime = (blockedUsers.get(ws)! - Date.now()) / 1000;
        if (remainingTime > 0) {
          ws.send(JSON.stringify({
            type: 'system',
            content: `[SERVER]: You are temporarily blocked. Try again in ${remainingTime.toFixed(1)} seconds.`,
          }));
          return;
        }
        else {
          blockedUsers.delete(ws);
        }
      }

      if (!checkRateLimit(ws)) {
        ws.send(JSON.stringify({
          type: 'system',
          content: '[SERVER]: You are sending messages too quickly. Slow down!',
        }));
        return;
      }

      // Handle login
      if (parsedData.type === 'login') {
        const { username, password } = parsedData;

        // Check if username is already connected
        for (const [_, existingUser] of users) {
          if (existingUser === username) {
            ws.send(JSON.stringify({
              type: 'system',
              content: 'Login failed: User already connected',
            }));
            return;
          }
        }

        // Validate credentials
        if (validateCredentials(username, password)) {
          users.set(ws, username);
          console.log(`[SERVER] ${username} has logged in.`);
          ws.send(JSON.stringify({ type: 'system', content: 'Login successful' }));
          broadcast(`[SERVER]: ${username} has joined the chat.`, ws);
          sendUserList();
        }
        else {
          ws.send(JSON.stringify({ type: 'system', content: 'Login failed' }));
        }
        return;
      }

      // Handle chat messages
      if (parsedData.type === 'message') {
        const sender = users.get(ws) || 'Unknown';
        console.log(`[SERVER] ${sender} says: ${parsedData.message}`);
        broadcast(`[${sender}]: ${parsedData.message}`, ws);
        return;
      }

    }
    catch (error) {
      console.error('[SERVER] Error processing message:', error);
    }
  });

  ws.on('close', () => {
    const username = users.get(ws);
    if (username) {
      console.log(`[SERVER] ${username} has disconnected.`);
      setTimeout(() => {
        if (!users.has(ws)) {
          users.delete(ws);
          broadcast(`[SERVER]: ${username} has left the chat.`);
          sendUserList();
        }
      }, RECONNECT_TIMEOUT);
    }

    stopHeartbeat(ws);
  });

  ws.send(JSON.stringify({ type: 'system', content: 'Welcome to the WebSocket server!' }));
});

function checkRateLimit(ws: WebSocket): boolean {
  const now = Date.now();
  const timestamps = messageTimestamps.get(ws) || [];
  const newTimestamps = timestamps.filter((timestamp) => now - timestamp < 1000);
  newTimestamps.push(now);
  messageTimestamps.set(ws, newTimestamps);

  if (newTimestamps.length > RATE_LIMIT) {
    console.log('[SERVER] User exceeded rate limit. Blocking temporarily.');
    blockedUsers.set(ws, Date.now() + BLOCK_DURATION);
    return false;
  }

  return true;
}

function broadcast(message: string, senderWs?: WebSocket) {
  console.log(`[SERVER] Broadcasting message: ${message}`);

  wss.clients.forEach((client) => {
    if (client !== senderWs && client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify({ type: 'chat', content: message }));
    }
  });
}

function sendUserList() {
  const userList = Array.from(users.values());
  const userListMessage = JSON.stringify({ type: 'userList', users: userList });

  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(userListMessage);
    }
  });
}

function sendHeartbeats() {
  wss.clients.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'ping' }));
    }
  });
}

function stopHeartbeat(ws: WebSocket) {
  if (heartbeatMap.has(ws)) {
    clearInterval(heartbeatMap.get(ws)!);
    heartbeatMap.delete(ws);
  }
}

setInterval(sendHeartbeats, HEARTBEAT_INTERVAL);
