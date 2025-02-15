import { WebSocket } from 'ws';
import readline from 'readline';
import { exit } from 'process';

let username: string | undefined;
let password: string | undefined;
let ws: WebSocket | null = null;
let shouldReconnect = true;
let isLoggedIn = false;

const SERVER_IP = '127.0.0.1';
const SERVER_URL = `wss://${SERVER_IP}:8080`;

function connectWebSocket() {
  ws = new WebSocket(SERVER_URL, { rejectUnauthorized: false });

  console.log('Connecting to server...');

  const connectionTimeout = setTimeout(() => {
    console.log('[ERROR] Server is unreachable. Please check if the server is running.');
    process.exit(1);
  }, 5000);

  ws.on('open', () => {
    clearTimeout(connectionTimeout);
    console.log('[CONNECTED] Successfully connected to the server.');
  });

  let welcomeMessageReceived = false;

  ws.on('message', (data) => {
    try {
      const message = JSON.parse(data.toString());

      if (message.type === 'system') {
        console.log(`[SERVER]: ${message.content}`);
        welcomeMessageReceived = true;

        if (!isLoggedIn && message.content.includes('Welcome')) {
          console.log('[CONNECTED] Please enter your credentials:');
          console.log('Username:');
        }

        // Handle login response
        if (message.content === 'Login successful') {
          isLoggedIn = true;
          console.log('You can now start chatting. Type a message, send a file using "/send <file_path>", or type "/logout" to disconnect.');
        }
        else if (message.content === 'Login failed' || message.content.includes('User already connected')) {
          username = undefined;
          password = undefined;
          console.log('[LOGIN] Please try again.');
          console.log('Username:');
        }
      }
      else if (message.type === 'chat') {
        console.log(message.content);
      }
      else if (message.type === 'userList') {
        console.log(`[ACTIVE USERS]: ${message.users.join(', ')}`);
      }
      else if (message.type === 'ping') {
        ws!.send(JSON.stringify({ type: 'pong' }));
      }
    }
    catch {
      console.log(`[SERVER]: ${data.toString()}`);
    }
  });

  ws.on('error', (err) => {
    console.error('[ERROR]', err);
  });

  ws.on('close', () => {
    console.log('[DISCONNECTED]');

    if (shouldReconnect) {
      console.log('[RECONNECTING] Trying to reconnect in 10 seconds...');
      setTimeout(connectWebSocket, 10000);
    }
  });

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  rl.on('line', (input: string) => {
    if (!isLoggedIn) {
      if (!username) {
        username = input.trim();
        console.log('Password:');
      }
      else if (!password) {
        password = input.trim();
        console.log(`[LOGIN] Logging in as ${username}`);
        ws!.send(JSON.stringify({ type: 'login', username, password }));
      }
    }
    else if (input === '/logout') {
      console.log('[CLIENT] Logging out...');
      shouldReconnect = false;
      ws!.send(JSON.stringify({ type: 'logout', username }));

      ws!.once('close', () => {
        ws = null;
        username = undefined;
        password = undefined;
        isLoggedIn = false;
        shouldReconnect = true;

        // Restart the connection process after a brief delay
        setTimeout(() => {
          connectWebSocket();
        }, 1000);
      });

      ws!.close();
      exit();
    }
    else {
      if (!ws || ws.readyState !== WebSocket.OPEN) {
        console.log('[ERROR] Connection lost. Reconnecting...');
        connectWebSocket();
        return;
      }
      ws!.send(JSON.stringify({ type: 'message', message: input.trim() }));
    }
  });
}

connectWebSocket();
