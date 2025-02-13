import { WebSocket } from 'ws';
import readline from 'readline';
import fs from 'fs';
import path from 'path'; //Import path module for file path handling


// create the websocket
const ws = new WebSocket('wss://localhost:8080', {
  rejectUnauthorized: false,
});

console.log('Connecting to server...');

//handle recieved messages from the server
ws.on('message', (data) => {
  const message = data.toString();

  // Ensure "Welcome" message appears right after "Connecting to server..."
  if (message.includes('Welcome to the WebSocket server!')) {
    console.log(`[SERVER]: ${message}`);
    console.log('[CONNECTED] Please enter your credentials:');
    console.log('Username:');
  } else {
    console.log(`[SERVER]: ${message}`);
  }
});

ws.on('error', (err) => {
  console.error('[ERROR]', err);
});





//File where user loging details are stored
const loginFile = 'accounts.json';

if (!fs.existsSync(loginFile)) {
  fs.writeFileSync(loginFile, JSON.stringify([]));
}

const userData = JSON.parse(fs.readFileSync(loginFile, 'utf-8'));


// get user input from cmdline
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

let username: string | undefined;
let password: string | undefined;

rl.on('line', (input: string) => {
  if (!username) {
    username = input.trim();
    console.log('Password: ');
  } else if (!password) {
    password = input.trim();
    console.log(`[LOGIN] Attempting to login with ${username}`);
    ws.send(JSON.stringify({ username, password }));

    //close input
    rl.close();
  }
});



// TODO: make it so i can connect with wss (secure) instead of ws (insecure)
