import { WebSocket } from 'ws';
import readline from 'readline';

const ws = new WebSocket('wss://localhost:8080', {
  rejectUnauthorized: false,
});

console.log('Connecting to server...');

let welcomeMessageReceived = false;

ws.on('message', (data) => {
  try {
    const message = JSON.parse(data.toString());

    // Display system messages such as welcome messages or notifications
    if (message.type === 'system') {
      console.log(`[SERVER]: ${message.content}`);
      welcomeMessageReceived = true;
    } 
    // Display public chat messages
    else if (message.type === 'chat') {
      console.log(message.content);
    } 
    // Display list of active users
    else if (message.type === 'userList') {
      console.log(`[ACTIVE USERS]: ${message.users.join(', ')}`);
    }

    // Show credentials prompt after welcome message
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

// Handle disconnection
ws.on('close', () => {
  console.log('[DISCONNECTED] You have left the chat room.');
  process.exit(0); 
});

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

let username: string | undefined;
let password: string | undefined;

// Handle user input
rl.on('line', (input: string) => {
  if (!username) {
    username = input.trim();
    console.log('Password:');
  } else if (!password) {
    password = input.trim();
    console.log(`[LOGIN] Logging in as ${username}`);
    ws.send(JSON.stringify({ username, password }));
    console.log('You can now start chatting. Type a message, send a file using "/send <file_path>", or type "/logout" to disconnect.');
  } else if (input === '/logout') {
    console.log('[CLIENT] Logging out...');
    ws.close(); // Close the WebSocket connection
  } else {
    ws.send(JSON.stringify({ message: input.trim() }));
  }
});
