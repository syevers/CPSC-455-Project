import { readFileSync } from 'fs';
import { WebSocketServer } from 'ws';
import https from 'https';

const PORT = 8080;

// https server options
const options = {
  key: readFileSync('../certs/private.pem'),
  cert: readFileSync('../certs/public.pem'),
};

const server = https.createServer(options).listen(PORT, () => {
  console.log(`[SERVER] Secure WebSocket server running on wss://localhost:${PORT}`);
});

//Create a WebSocket server and attach it to the HTTPS server
const wss = new WebSocketServer({
  server: server,
});

console.log(`[SERVER] Listening for WebSocket connections on port ${PORT}`);

wss.on('connection', function connection(ws) {
  // console.log(wss.clients);
  console.log('[SERVER] Client connected.');
  ws.on('error', console.error);

  ws.on('message', function message(data) {
    console.log(`[SERVER] Received: ${data.toString()}`);
    ws.send(`Hello, client! You sent: ${data.toString()}`);
  });

  ws.send('Welcome to the WebSocket server!');
});
