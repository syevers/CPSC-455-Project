import { WebSocket } from 'ws';
import * as readline from 'node:readline';

const ws = new WebSocket('ws://localhost:8080');

console.log('Connecting to server...');

let username: string, password: string;

ws.on('connect', function connection(ws) {
  console.log(['[CONNECTED]:']);

});
ws.on('error', console.error);

// get user input from cmdline
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

rl.on('line', (input: any) => {
  console.log(input);
});


// TODO: make it so i can connect with wss (secure) instead of ws (insecure)
