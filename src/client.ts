import { WebSocket } from 'ws';
import readline from 'readline';

let username: string | undefined;
let password: string | undefined;
let ws: WebSocket | null = null;
let shouldReconnect = true; // Flag to control reconnection behavior

const SERVER_IP = '127.0.0.1'; // Replace with the server's IP address
const SERVER_URL = `wss://${SERVER_IP}:8080`; // WebSocket URL

function connectWebSocket() {
  ws = new WebSocket(SERVER_URL, { rejectUnauthorized: false });

  console.log('Connecting to server...');

  const connectionTimeout = setTimeout(() => {
    console.log('[ERROR] Server is unreachable. Please check if the server is running.');
    process.exit(1);
  }, 5000); // Exit if no connection after 5 seconds

  ws.on('open', () => {
    clearTimeout(connectionTimeout); // Cancel timeout if connection is successful
    console.log('[CONNECTED] Successfully connected to the server.');
  });

  let welcomeMessageReceived = false;

  ws.on('message', (data) => {
    try {
      const message = JSON.parse(data.toString());

      if (message.type === 'system') {
        console.log(`[SERVER]: ${message.content}`);
        welcomeMessageReceived = true;

        // Ensure login prompt appears only after welcome message
        if (!username && message.type === 'system' && message.content.includes('Welcome') && !welcomeMessageReceived) {
          welcomeMessageReceived = true; // Prevent multiple prompts
          promptLogin();
        } 
      } else if (message.type === 'chat') {
        console.log(message.content);
      } else if (message.type === 'userList') {
        console.log(`[ACTIVE USERS]: ${message.users.join(', ')}`);
      } else if (message.type === 'ping') {
        ws!.send(JSON.stringify({ type: 'pong' })); // Respond to server pings
      }

      // Show login prompt only after welcome message
      if (welcomeMessageReceived && !username) {
        console.log('[CONNECTED] Please enter your credentials:');
        console.log('Username:');
      }
    } catch {
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
      setTimeout(connectWebSocket, 10000); // Wait 10 seconds before reconnecting
    } else {
      console.log('[CLIENT] You have logged out.');
    }
  });

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  function promptLogin() {
    if (!username) {
      console.log('Username:');
    }
  }

  rl.on('line', (input: string) => {
    if (!username) {
      username = input.trim();
      console.log('Password:');
    } else if (!password) {
      password = input.trim();
      console.log(`[LOGIN] Logging in as ${username}`);
      ws!.send(JSON.stringify({ username, password }));
      console.log('You can now start chatting. Type a message, send a file using "/send <file_path>", or type "/logout" to disconnect.');
    } else if (input === '/logout') {
      console.log('[CLIENT] Logging out...'); 
      shouldReconnect = false; // Prevent auto-reconnect
      ws!.send(JSON.stringify({ type: 'logout', username }));

    // Ensure WebSocket closes fully before continuing
      ws!.once('close', () => {
        ws = null;
        username = undefined;
        password = undefined;
        
    });
    ws!.close(); // Close connection properly

    } else {
      if (!ws || ws.readyState !== WebSocket.OPEN) {
        console.log("[ERROR] Connection lost. Reconnecting...");
        connectWebSocket();
        return;
      }
      ws!.send(JSON.stringify({ message: input.trim() }));
    }
  });
}
// Start WebSocket connection
connectWebSocket();
