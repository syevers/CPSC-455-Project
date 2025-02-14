import { readFileSync } from 'fs';
import { WebSocketServer, WebSocket } from 'ws';
import https from 'https';
import { fileURLToPath } from 'url';
import path from 'path';

// Fix __dirname for ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 8080;

// SSL options for secure WebSocket connection
const options = {
  key: readFileSync('../certs/private.pem'),
  cert: readFileSync('../certs/public.pem'),
};

// Create WebSocket Server
const server = https.createServer(options).listen(PORT, () => {
  console.log(`[SERVER] Running on wss://localhost:${PORT}`);
});

const wss = new WebSocketServer({ server });
const users = new Map<WebSocket, string>();

// Maps to track rate limiting
const messageTimestamps = new Map<WebSocket, number[]>(); // Track user messages
const blockedUsers = new Map<WebSocket, number>(); // Store temporarily blocked users

const RATE_LIMIT = 5; // Max messages per second
const BLOCK_DURATION = 10000; // Block duration in milliseconds (10 sec)

console.log(`[SERVER] Listening for connections on port ${PORT}`);

wss.on('connection', (ws) => {
  console.log('[SERVER] New client connected.');

  ws.on('error', console.error);

  ws.on('message', (data) => {
    try {
      const parsedData = JSON.parse(data.toString());

      // Check if user is temporarily blocked
      if (blockedUsers.has(ws)) {
        const remainingTime = (blockedUsers.get(ws)! - Date.now()) / 1000;
        if (remainingTime > 0) {
          ws.send(JSON.stringify({ type: 'system', content: `[SERVER]: You are temporarily blocked. Try again in ${remainingTime.toFixed(1)} seconds.` }));
          return;
        } else {
          blockedUsers.delete(ws);
        }
      }

      // Apply rate limiting
      if (!checkRateLimit(ws)) {
        ws.send(JSON.stringify({ type: 'system', content: '[SERVER]: You are sending messages too quickly. Slow down!' }));
        return;
      }

      // Handle user login
      if (parsedData.username && parsedData.password) {
        users.set(ws, parsedData.username);
        console.log(`[SERVER] ${parsedData.username} has logged in.`);
        broadcast(`[SERVER]: ${parsedData.username} has joined the chat.`, ws);
        sendUserList();
        return;
      }

      // Handle chat messages
      if (parsedData.message) {
        const sender = users.get(ws) || 'Unknown';
        console.log(`[SERVER] ${sender} says: ${parsedData.message}`);
        broadcast(`[${sender}]: ${parsedData.message}`, ws);
        return;
      }
    } catch (error) {
      console.error('[SERVER] Error processing message:', error);
    }
  });

  ws.on('close', () => {
    const username = users.get(ws);
    if (username) {
      console.log(`[SERVER] ${username} has disconnected.`);
      users.delete(ws);
      broadcast(`[SERVER]: ${username} has left the chat.`);
      sendUserList();
    }
  });

  ws.send(JSON.stringify({ type: 'system', content: 'Welcome to the WebSocket server!' }));
});

// Function to enforce rate limits
function checkRateLimit(ws: WebSocket): boolean {
  const now = Date.now();
  const timestamps = messageTimestamps.get(ws) || [];
  
  // Remove timestamps older than 1 second
  const newTimestamps = timestamps.filter((timestamp) => now - timestamp < 1000);
  newTimestamps.push(now);
  messageTimestamps.set(ws, newTimestamps);

  // If user exceeds RATE_LIMIT, block them temporarily
  if (newTimestamps.length > RATE_LIMIT) {
    console.log(`[SERVER] User exceeded rate limit. Blocking temporarily.`);
    blockedUsers.set(ws, Date.now() + BLOCK_DURATION);
    return false;
  }

  return true;
}

// Function to broadcast chat messages
function broadcast(message: string, senderWs?: WebSocket) {
  console.log(`[SERVER] Broadcasting message: ${message}`);
  
  wss.clients.forEach((client) => {
    if (client !== senderWs && client.readyState === WebSocket.OPEN) {
      console.log(`[SERVER] Sending message to client: ${message}`);
      client.send(JSON.stringify({ type: 'chat', content: message }));
    }
  });
}

// Function to send active user list
function sendUserList() {
  const userList = Array.from(users.values());
  const userListMessage = JSON.stringify({ type: 'userList', users: userList });

  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(userListMessage);
    }
  });
}
