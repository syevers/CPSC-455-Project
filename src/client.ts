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

console.log(`[SERVER] Listening for connections on port ${PORT}`);

wss.on('connection', (ws) => {
  console.log('[SERVER] New client connected.');

  ws.on('error', console.error);

  ws.on('message', (data) => {
    try {
      const parsedData = JSON.parse(data.toString());

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
