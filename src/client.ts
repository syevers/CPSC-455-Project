import { WebSocket } from 'ws';
import os from 'node:os';
import readline from 'readline';
import { exit } from 'process';
import fs from 'fs';
import crypto from 'crypto';
import path from 'path';



let username: string | undefined;
let password: string | undefined;
let ws: WebSocket | null = null;
let shouldReconnect = true;
let isLoggedIn = false;

function sendEncryptedFile(filePath: string, recipient: string) {
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    console.log('[CLIENT] WebSocket is not connected.');
    return;
  }

  const filename = path.basename(filePath);
  const fileBuffer = fs.readFileSync(filePath);

  const key = crypto.randomBytes(32); // AES-256
  const iv = crypto.randomBytes(12);  // GCM IV

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(fileBuffer), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const payload = {
    type: 'file',
    to: recipient,
    filename,
    data: Buffer.concat([encrypted, authTag]).toString('base64'),
    iv: iv.toString('base64'),
    key: key.toString('base64')
  };

  ws.send(JSON.stringify(payload));
  console.log(`[CLIENT] Sent encrypted file "${filename}" to ${recipient}`);
}

// Handle incoming encrypted file
function handleIncomingFile(msg: any) {
  const { filename, from, data, iv, key } = msg;
  const encryptedData = Buffer.from(data, 'base64');
  const fileKey = Buffer.from(key, 'base64');
  const fileIV = Buffer.from(iv, 'base64');

  const authTag = encryptedData.slice(-16);
  const encrypted = encryptedData.slice(0, -16);

  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', fileKey, fileIV);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);

    const savePath = `received_from_${from}_${filename}`;
    fs.writeFileSync(savePath, decrypted);
    console.log(`[CLIENT] Received and decrypted file saved as "${savePath}"`);
  } catch (err) {
    console.error('[CLIENT] Failed to decrypt file:', err);
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

const SERVER_IP = getLocalIPAddress();
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
      else if (message.type === 'file') {
        const { filename, from, data, iv, key } = message;
        const encryptedData = Buffer.from(data, 'base64');
        const fileKey = Buffer.from(key, 'base64');
        const fileIV = Buffer.from(iv, 'base64');

        const authTag = encryptedData.slice(-16);
        const encrypted = encryptedData.slice(0, -16);

        try {
          const decipher = crypto.createDecipheriv('aes-256-gcm', fileKey, fileIV);
          decipher.setAuthTag(authTag);
          const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);

          const savePath = `received_from_${from}_${filename}`;
          fs.writeFileSync(savePath, decrypted);
          console.log(`[CLIENT]  Received file "${filename}" from ${from}, saved as "${savePath}"`);
        } catch (err) {
          console.error('[CLIENT]  Failed to decrypt file:', err);
        }
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
    else if (input.startsWith('/send ')) {
      const [ , filePath, recipient ] = input.trim().split(' ');
      if (!filePath || !recipient) {
        console.log('[USAGE] /send <file_path> <recipient>');
        return;
      }

      sendEncryptedFile(filePath, recipient); // call your encryption + sending
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
