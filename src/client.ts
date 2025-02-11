import { WebSocket } from 'ws';
import readline from 'readline';
import fs from 'fs';


// create the websocket
const ws = new WebSocket('wss://localhost:8080', {
  rejectUnauthorized: false,
});

console.log('Connecting to server...');

ws.on('error', console.error);

ws.on('open', () => {
  console.log('[CONNECTED] Please enter your credentials:\nUsername:');
  // ws.send('this is a test message');
});

const loginFile = 'accounts.json';
if (!fs.existsSync(loginFile)) {
  fs.writeFileSync(loginFile, JSON.stringify([]));
}

const userData = JSON.parse(fs.readFileSync(loginFile));
console.log();


// get user input from cmdline
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

let username, password;
rl.on('line', (input: string) => {
  if (!username) {
    username = input.trim();
    console.log('Password: ');

  }
  console.log(input);
});


// TODO: make it so i can connect with wss (secure) instead of ws (insecure)
