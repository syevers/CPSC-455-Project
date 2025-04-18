import bcrypt from 'bcrypt';
import crypto, { KeyObject } from 'crypto'; // Import crypto module
import { existsSync, readFileSync, writeFileSync } from 'fs';
import type { IncomingMessage } from 'http';
import https from 'https';
import { Collection, Db, MongoClient } from 'mongodb'; // Import MongoDB types
import path from 'path';
import { fileURLToPath } from 'url';
import { WebSocket, WebSocketServer, type RawData } from 'ws';

// Constants and Setup
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = 8080;
const options = {
  // Still use user certs for the HTTPS server itself
  key: readFileSync(path.join(__dirname, '../certs/private.pem')),
  cert: readFileSync(path.join(__dirname, '../certs/public.pem')),
};
const ACCOUNTS_PATH = path.join(__dirname, 'accounts.json');
const RATE_LIMIT = 20;
const RATE_LIMIT_BLOCK_DURATION = 10000;
const HEARTBEAT_INTERVAL = 30000;
const SALT_ROUNDS = 10;
const MAX_FILE_SIZE = 10 * 1024 * 1024;
const MAX_CHUNK_SIZE = 64 * 1024;

// WebSocket Server Initialization
const server = https.createServer(options);
const wss = new WebSocketServer({ server });

// Brute-Force Protection Constants
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_BLOCK_DURATION = 60 * 1000;
const ATTEMPT_WINDOW = 5 * 60 * 1000;

// MongoDB Setup
// REPLACE WITH YOUR ACTUAL MONGODB CONNECTION STRING
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017';
const MONGODB_DB_NAME = 'secureChat';
const MONGODB_LOG_COLLECTION = 'chatLogs';

let db: Db | null = null;
let chatLogCollection: Collection<ChatLogDocument> | null = null;

// Server Keys
let serverPrivateKey: KeyObject | null = null;
let serverPublicKeyPem: string | null = null;

// Interfaces
interface UserAccount {
  username: string;
  passwordHash: string;
}
interface AccountsData {
  users: UserAccount[];
}
// Interface for MongoDB log documents
interface ChatLogDocument {
  timestamp: Date;
  type: 'broadcast' | 'private' | 'file_request' | 'file_accept' | 'file_reject'; // Add more types as needed
  sender: string;
  recipient?: string; // Optional for broadcast/system/file events
  messageContent?: string; // Store decrypted message content for text messages
  fileInfo?: { name: string; size: number }; // Optional for file transfers
  ipAddress: string; // Log sender's IP
}

// Message Types
enum ServerMessageType {
  SYSTEM = 'system',
  USER_LIST = 'userList',
  SERVER_PUBLIC_KEY = 'server_public_key', // For sending server's key to client
  RECEIVE_MESSAGE = 'receive_message', // Generic message receipt type
  RECEIVE_PUBLIC_KEY = 'receive_public_key', // For receiving user keys
  PONG = 'pong',
  PING = 'ping',
  INCOMING_FILE_REQUEST = 'incoming_file_request',
  FILE_ACCEPT_NOTICE = 'file_accept_notice',
  FILE_REJECT_NOTICE = 'file_reject_notice',
  FILE_CHUNK_RECEIVE = 'file_chunk_receive',
}

enum ClientMessageType {
  LOGIN = 'login',
  LOGOUT = 'logout',
  SEND_MESSAGE = 'send_message', // Generic message sending type
  SHARE_PUBLIC_KEY = 'share_public_key', // Client shares its key
  REQUEST_PUBLIC_KEY = 'request_public_key', // Client requests another user's key (for files)
  PING = 'ping',
  PONG = 'pong',
  FILE_TRANSFER_REQUEST = 'file_transfer_request',
  FILE_TRANSFER_ACCEPT = 'file_transfer_accept',
  FILE_TRANSFER_REJECT = 'file_transfer_reject',
  FILE_CHUNK = 'file_chunk',
}

// Message Interfaces
interface BaseMessage {
  type: ClientMessageType | ServerMessageType;
}
interface LoginMessage extends BaseMessage {
  type: ClientMessageType.LOGIN;
  username: string;
  password?: string;
}
interface LogoutMessage extends BaseMessage {
  type: ClientMessageType.LOGOUT;
  username?: string;
}
// Client shares its key (SPKI Base64 format)
interface SharePublicKeyMessage extends BaseMessage {
  type: ClientMessageType.SHARE_PUBLIC_KEY;
  publicKey: string;
}
interface RequestPublicKeyMessage extends BaseMessage {
  type: ClientMessageType.REQUEST_PUBLIC_KEY;
  username: string;
}
interface PongMessage extends BaseMessage {
  type: ClientMessageType.PONG;
}

// Message sent from Client -> Server
interface ClientSendMessage extends BaseMessage {
  type: ClientMessageType.SEND_MESSAGE;
  recipient?: string; // Undefined or null for broadcast
  payload: {
    iv: string; // AES IV (base64)
    encryptedKey: string; // AES key encrypted with SERVER's public key (base64)
    ciphertext: string; // Message content encrypted with AES key (base64)
  };
}
// Message sent from Server -> Client
interface ServerReceiveMessage extends BaseMessage {
  type: ServerMessageType.RECEIVE_MESSAGE;
  sender: string;
  isBroadcast: boolean;
  payload: {
    iv: string; // AES IV (base64)
    encryptedKey: string; // AES key encrypted with RECIPIENT's public key (base64)
    ciphertext: string; // Message content encrypted with AES key (base64)
  };
}
// Server sends its public key (PEM format)
interface ServerPublicKeyMessage extends BaseMessage {
  type: ServerMessageType.SERVER_PUBLIC_KEY;
  publicKey: string; // PEM format
}

// File Transfer Interfaces
interface FileInfo {
  name: string;
  size: number;
  type: string;
  iv: string;
  encryptedKey: string;
}
interface FileTransferRequestMessage extends BaseMessage {
  type: ClientMessageType.FILE_TRANSFER_REQUEST;
  recipient: string;
  fileInfo: FileInfo;
}
interface FileTransferAcceptMessage extends BaseMessage {
  type: ClientMessageType.FILE_TRANSFER_ACCEPT;
  sender: string;
  fileInfo: { name: string; size: number };
}
interface FileTransferRejectMessage extends BaseMessage {
  type: ClientMessageType.FILE_TRANSFER_REJECT;
  sender: string;
  fileInfo: { name: string };
}
interface FileChunkMessage extends BaseMessage {
  type: ClientMessageType.FILE_CHUNK;
  recipient: string;
  fileInfo: { name: string };
  chunkData: string;
  chunkIndex: number;
  isLastChunk: boolean;
}

interface IncomingFileRequestMessage extends BaseMessage {
  type: ServerMessageType.INCOMING_FILE_REQUEST;
  sender: string;
  fileInfo: FileInfo;
}

interface FileAcceptNoticeMessage extends BaseMessage {
  type: ServerMessageType.FILE_ACCEPT_NOTICE;
  recipient: string;
  fileInfo: { name: string; size: number };
}
interface FileRejectNoticeMessage extends BaseMessage {
  type: ServerMessageType.FILE_REJECT_NOTICE;
  recipient: string;
  fileInfo: { name: string };
}
interface FileChunkReceiveMessage extends BaseMessage {
  type: ServerMessageType.FILE_CHUNK_RECEIVE;
  sender: string;
  fileInfo: { name: string };
  chunkData: string;
  chunkIndex: number;
  isLastChunk: boolean;
}

// Other Server -> Client Messages
interface SystemMessage extends BaseMessage {
  type: ServerMessageType.SYSTEM;
  content: string;
}
interface UserListMessage extends BaseMessage {
  type: ServerMessageType.USER_LIST;
  users: string[];
}
// Server sends user's public key
interface ReceivePublicKeyServerMessage extends BaseMessage {
  type: ServerMessageType.RECEIVE_PUBLIC_KEY;
  username: string;
  publicKey: string;
}

// Type Guards
function isLoginMessage(msg: any): msg is LoginMessage {
  return msg?.type === ClientMessageType.LOGIN && typeof msg.username === 'string';
}
function isLogoutMessage(msg: any): msg is LogoutMessage {
  return msg?.type === ClientMessageType.LOGOUT;
}
function isSharePublicKeyMessage(msg: any): msg is SharePublicKeyMessage {
  return msg?.type === ClientMessageType.SHARE_PUBLIC_KEY && typeof msg.publicKey === 'string';
} // Basic check
function isRequestPublicKeyMessage(msg: any): msg is RequestPublicKeyMessage {
  return msg?.type === ClientMessageType.REQUEST_PUBLIC_KEY && typeof msg.username === 'string';
}
function isPongMessage(msg: any): msg is PongMessage {
  return msg?.type === ClientMessageType.PONG;
}
function isClientSendMessage(msg: any): msg is ClientSendMessage {
  return (
    msg?.type === ClientMessageType.SEND_MESSAGE &&
    typeof msg.payload?.iv === 'string' &&
    typeof msg.payload?.encryptedKey === 'string' &&
    typeof msg.payload?.ciphertext === 'string' &&
    (msg.recipient === undefined || msg.recipient === null || typeof msg.recipient === 'string')
  );
}
// File Transfer Guards
function isFileTransferRequest(msg: any): msg is FileTransferRequestMessage {
  return (
    msg?.type === ClientMessageType.FILE_TRANSFER_REQUEST &&
    typeof msg.recipient === 'string' &&
    typeof msg.fileInfo?.name === 'string' &&
    typeof msg.fileInfo?.size === 'number' &&
    typeof msg.fileInfo?.type === 'string' &&
    typeof msg.fileInfo?.iv === 'string' &&
    typeof msg.fileInfo?.encryptedKey === 'string'
  );
}

function isFileTransferAccept(msg: any): msg is FileTransferAcceptMessage {
  return (
    msg?.type === ClientMessageType.FILE_TRANSFER_ACCEPT &&
    typeof msg.sender === 'string' &&
    typeof msg.fileInfo?.name === 'string' &&
    typeof msg.fileInfo?.size === 'number'
  );
}

function isFileTransferReject(msg: any): msg is FileTransferRejectMessage {
  return (
    msg?.type === ClientMessageType.FILE_TRANSFER_REJECT &&
    typeof msg.sender === 'string' &&
    typeof msg.fileInfo?.name === 'string'
  );
}

function isFileChunk(msg: any): msg is FileChunkMessage {
  return (
    msg?.type === ClientMessageType.FILE_CHUNK &&
    typeof msg.recipient === 'string' &&
    typeof msg.fileInfo?.name === 'string' &&
    typeof msg.chunkData === 'string' &&
    typeof msg.chunkIndex === 'number' &&
    typeof msg.isLastChunk === 'boolean'
  );
}

// Crypto Helper Functions

// Decrypts data using RSA-OAEP with the server's private key
function decryptWithServerKey(encryptedDataB64: string): Buffer | null {
  if (!serverPrivateKey) {
    console.error('[CRYPTO] Server private key not loaded.');
    return null;
  }
  try {
    const encryptedBuffer = Buffer.from(encryptedDataB64, 'base64');
    const decryptedBuffer = crypto.privateDecrypt(
      {
        key: serverPrivateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      encryptedBuffer
    );
    return decryptedBuffer;
  } catch (error) {
    console.error('[CRYPTO] RSA decryption with server key failed:', error);
    return null;
  }
}

// Converts SPKI Base64 key to PEM format
function spkiBase64ToPem(spkiBase64: string): string {
  // Add PEM headers and footers, and wrap lines every 64 characters
  const pemContents = spkiBase64.match(/.{1,64}/g)?.join('\n') || '';
  return `-----BEGIN PUBLIC KEY-----\n${pemContents}\n-----END PUBLIC KEY-----`;
}

// Encrypts data using RSA-OAEP with a recipient's public key
function encryptWithRecipientKey(
  recipientPublicKeySpkiBase64: string,
  dataBuffer: Buffer
): string | null {
  try {
    // Convert SPKI Base64 to PEM format for Node's crypto module
    const recipientPublicKeyPem = spkiBase64ToPem(recipientPublicKeySpkiBase64);
    const publicKey = crypto.createPublicKey(recipientPublicKeyPem);
    const encryptedBuffer = crypto.publicEncrypt(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      dataBuffer
    );
    return encryptedBuffer.toString('base64');
  } catch (error) {
    console.error('[CRYPTO] RSA encryption with recipient key failed:', error);
    return null;
  }
}

// Decrypts message content using AES-GCM.
function decryptAesGcm(aesKey: Buffer, ivB64: string, ciphertextB64: string): string | null {
  try {
    const iv = Buffer.from(ivB64, 'base64');
    const ciphertext = Buffer.from(ciphertextB64, 'base64');
    const authTagLength = 16;
    if (ciphertext.length < authTagLength) {
      throw new Error('Invalid ciphertext length for GCM.');
    }
    const encryptedPart = ciphertext.subarray(0, ciphertext.length - authTagLength);
    const authTag = ciphertext.subarray(ciphertext.length - authTagLength);
    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encryptedPart, undefined, 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    console.error('[CRYPTO] AES-GCM decryption failed:', error);
    return null;
  }
}

// Helper Functions
function initializeAccountsFile(): AccountsData | null {
  if (!existsSync(ACCOUNTS_PATH)) {
    console.log('[SRV] Creating accounts.json:', ACCOUNTS_PATH);
    const e: AccountsData = { users: [] };
    try {
      writeFileSync(ACCOUNTS_PATH, JSON.stringify(e, null, 2), 'utf8');
      return e;
    } catch (w) {
      console.error('[SRV] Failed create accounts.json:', w);
      return { users: [] };
    }
  }
  return null;
}

function loadAccounts(): AccountsData {
  try {
    const i = initializeAccountsFile();
    if (i) return i;
    const d = readFileSync(ACCOUNTS_PATH, 'utf8');
    const p = JSON.parse(d);
    if (!p || !Array.isArray(p.users)) {
      throw new Error('Invalid format');
    }
    p.users = p.users
      .map((u: any) => ({ username: u.username, passwordHash: u.passwordHash || '' }))
      .filter(
        (u: UserAccount | null): u is UserAccount => u !== null && u.username && u.passwordHash
      );
    return p as AccountsData;
  } catch (e: any) {
    console.error('[SRV] Error load/parse accounts.json:', e.message, '. Resetting.');
    try {
      const em: AccountsData = { users: [] };
      writeFileSync(ACCOUNTS_PATH, JSON.stringify(em, null, 2), 'utf8');
      return em;
    } catch (w) {
      console.error('[SRV] Failed reset accounts.json:', w);
      return { users: [] };
    }
  }
}
function addNewUser(username: string, password?: string): boolean {
  if (!password) {
    console.log('[SRV] No password for new user:', username);
    return false;
  }
  try {
    const a = loadAccounts();
    if (a.users.some((u) => u.username.toLowerCase() === username.toLowerCase())) {
      console.log('[SRV] User already exists:', username);
      return false;
    }
    const h = bcrypt.hashSync(password, SALT_ROUNDS);
    a.users.push({ username, passwordHash: h });
    writeFileSync(ACCOUNTS_PATH, JSON.stringify(a, null, 2), 'utf8');
    console.log('[SRV] New user added successfully:', username);
    return true;
  } catch (e) {
    console.error('[SRV] Error adding new user:', e);
    return false;
  }
}
function validateCredentials(username: string, password?: string): boolean {
  const accounts = loadAccounts();
  if (!accounts || !Array.isArray(accounts.users)) {
    console.error('[SRV] Invalid accounts data.');
    return false;
  }
  try {
    const userAccount = accounts.users.find(
      (usr) => usr.username.toLowerCase() === username.toLowerCase()
    );
    if (!userAccount) {
      console.log('[SRV] User not found, creating:', username);
      if (!password) {
        console.log('[SRV] Cannot create user without password:', username);
        return false;
      }
      return addNewUser(username, password);
    } else {
      if (!password || !userAccount.passwordHash) {
        console.log(`[SRV] Login fail: Missing password/hash for ${username}`);
        return false;
      }
      const isValid = bcrypt.compareSync(password, userAccount.passwordHash);
      if (!isValid) {
        console.log(`[SRV] Login fail: Invalid password for ${username}`);
      }
      return isValid;
    }
  } catch (e) {
    console.error('[SRV] Error during credential validation:', e);
    return false;
  }
}
function checkRateLimit(ws: WebSocket): boolean {
  const n = Date.now();
  const t = messageTimestamps.get(ws) || [];
  const nt = t.filter((ts) => n - ts < 1000);
  nt.push(n);
  messageTimestamps.set(ws, nt);
  if (nt.length > RATE_LIMIT) {
    if (!rateLimitBlockedUsers.has(ws)) {
      const id = clientDataMap.get(ws)?.username || ws.toString();
      console.log(`[SRV] Rate limit exceeded (${nt.length}/${RATE_LIMIT}mps). Blocking: ${id}`);
      rateLimitBlockedUsers.set(ws, n + RATE_LIMIT_BLOCK_DURATION);
      try {
        ws.send(
          JSON.stringify({
            type: ServerMessageType.SYSTEM,
            content: `[SRV]: Rate limit exceeded. Blocked for ${
              RATE_LIMIT_BLOCK_DURATION / 1000
            }s.`,
          })
        );
      } catch (se) {
        console.error(
          `[SRV] Fail send rate limit msg to ${clientDataMap.get(ws)?.username || id}:`,
          se
        );
      }
    }
    return false;
  }
  if (rateLimitBlockedUsers.has(ws) && n > rateLimitBlockedUsers.get(ws)!) {
    rateLimitBlockedUsers.delete(ws);
    const id = clientDataMap.get(ws)?.username || ws.toString();
    console.log(`[SRV] Rate limit block expired for: ${id}`);
  }
  return true;
}

// Logging Function for database
async function logToMongo(logData: Omit<ChatLogDocument, 'timestamp'>): Promise<void> {
  if (!chatLogCollection) {
    console.error('[SRV-LOG] DB collection not available. Cannot log message.');
    return;
  }
  const documentToInsert: ChatLogDocument = { ...logData, timestamp: new Date() };
  try {
    const result = await chatLogCollection.insertOne(documentToInsert);
    if (!result.acknowledged) {
      console.warn('[SRV-LOG] DB insert not acknowledged for sender:', logData.sender);
    }
  } catch (error) {
    console.error('[SRV-LOG] Error logging message to DB:', error, 'Data:', documentToInsert);
  }
}

// Broadcast/Send Functions
function broadcastUserList() {
  const userList = Array.from(clientsByName.keys());
  console.log('[SRV] Broadcasting user list:', userList);
  const msg = JSON.stringify({ type: ServerMessageType.USER_LIST, users: userList });
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN && clientDataMap.has(client)) {
      try {
        client.send(msg);
      } catch (se) {
        console.error(
          `[SRV] Failed send user list to ${clientDataMap.get(client)?.username || '?'}:`,
          se
        );
      }
    }
  });
}
function sendToClient(ws: WebSocket, message: object) {
  if (ws.readyState === WebSocket.OPEN) {
    try {
      ws.send(JSON.stringify(message));
    } catch (se) {
      console.error(
        `[SRV] Failed send msg to ${clientDataMap.get(ws)?.username || '?'}:`,
        se,
        message
      );
    }
  } else {
    console.warn(
      `[SRV] Attempted send to non-open socket for ${clientDataMap.get(ws)?.username || '?'}`
    );
  }
}

// Connection Management
function handleDisconnect(ws: WebSocket) {
  const cd = clientDataMap.get(ws);
  const un = cd?.username;
  const id = ws.toString();
  console.log('[SRV] Handling disconnect for:', id, 'User:', un || 'N/A');
  stopHeartbeat(ws);
  let wasLoggedIn = false;
  if (un) {
    clientsByName.delete(un);
    publicKeys.delete(un);
    loginFailureCounts.delete(un);
    loginBlockedUsers.delete(un);
    wasLoggedIn = true;
    console.log(`[SRV] ${un} removed from active users.`);
  }
  clientDataMap.delete(ws);
  messageTimestamps.delete(ws);
  rateLimitBlockedUsers.delete(ws);
  console.log(`[SRV] Cleanup complete for WS: ${id}`);
  if (wasLoggedIn) {
    broadcastUserList();
  }
}
function startHeartbeat(ws: WebSocket) {
  stopHeartbeat(ws);
  const clientData = clientDataMap.get(ws);
  const clientId = clientData?.username || ws.toString();
  if (!clientData) {
    console.error(`[SRV] Cannot start heartbeat for ${clientId}: client data not found.`);
    return;
  }
  console.log(`[SRV] Starting heartbeat for ${clientId}`);
  clientData.isAlive = true;
  const intervalId = setInterval(() => {
    const currentClientData = clientDataMap.get(ws);
    const currentClientId = currentClientData?.username || ws.toString();
    if (!currentClientData) {
      console.warn(`[SRV] Heartbeat: Client data missing (WS ${ws.toString()}), stopping.`);
      if (heartbeatMap.has(ws)) {
        clearInterval(heartbeatMap.get(ws)!);
        heartbeatMap.delete(ws);
      }
      return;
    }
    if (currentClientData.isAlive === false) {
      console.log(`[SRV] Heartbeat failed (no pong) for ${currentClientId}. Terminating.`);
      handleDisconnect(ws);
      ws.terminate();
      return;
    }
    currentClientData.isAlive = false;
    try {
      if (ws.readyState === WebSocket.OPEN) {
        const pingMsg = { type: ServerMessageType.PING };
        ws.send(JSON.stringify(pingMsg));
      } else {
        console.log(
          `[SRV] Heartbeat: WS not open during ping for ${currentClientId}, cleaning up.`
        );
        handleDisconnect(ws);
      }
    } catch (sendError) {
      console.error(`[SRV] Failed send PING to ${currentClientId}:`, sendError);
      handleDisconnect(ws);
      ws.terminate();
    }
  }, HEARTBEAT_INTERVAL);
  heartbeatMap.set(ws, intervalId);
}
function stopHeartbeat(ws: WebSocket) {
  if (heartbeatMap.has(ws)) {
    clearInterval(heartbeatMap.get(ws)!);
    heartbeatMap.delete(ws);
  }
}

// MongoDB Connection Function
async function connectToMongo() {
  try {
    const client = new MongoClient(MONGODB_URI);
    await client.connect();
    db = client.db(MONGODB_DB_NAME);
    chatLogCollection = db.collection(MONGODB_LOG_COLLECTION);
    await chatLogCollection.createIndex({ timestamp: -1 });
    await chatLogCollection.createIndex({ sender: 1 });
    await chatLogCollection.createIndex({ recipient: 1 });
    await chatLogCollection.createIndex({ type: 1 });
    console.log(
      `[SRV-DB] Successfully connected to MongoDB: ${MONGODB_DB_NAME}/${MONGODB_LOG_COLLECTION}`
    );
  } catch (error) {
    console.error('[SRV-DB] Failed to connect to MongoDB:', error);
    process.exit(1);
  }
}

// State Management
interface ClientData {
  username: string;
  ipAddress: string;
  publicKeySpkiBase64?: string; // Store user's public key (SPKI Base64 format)
  isAlive?: boolean;
}

const clientDataMap = new Map<WebSocket, ClientData>();
const clientsByName = new Map<string, WebSocket>();
// Store user public keys as SPKI Base64
const publicKeys = new Map<string, string>();
const heartbeatMap = new Map<WebSocket, NodeJS.Timeout>();
const messageTimestamps = new Map<WebSocket, number[]>();
const rateLimitBlockedUsers = new Map<WebSocket, number>();
const loginFailureCounts = new Map<string, { count: number; lastAttempt: number }>();
const loginBlockedUsers = new Map<string, number>();

// Main Server Startup Logic
async function startServer() {
  console.log(`[SRV] Initializing...`);
  // Load server keys
  try {
    const privateKeyPath = path.join(__dirname, '../certs/server_private.pem');
    const publicKeyPath = path.join(__dirname, '../certs/server_public.pem');
    if (!existsSync(privateKeyPath) || !existsSync(publicKeyPath)) {
      console.error(`[FATAL] Server key pair not found in certs/ directory.`);
      process.exit(1);
    }
    const privateKeyPem = readFileSync(privateKeyPath, 'utf8');
    serverPublicKeyPem = readFileSync(publicKeyPath, 'utf8');
    serverPrivateKey = crypto.createPrivateKey(privateKeyPem);
    console.log('[SRV] Server key pair loaded successfully.');
  } catch (error) {
    console.error('[SRV] Failed to load server key pair:', error);
    process.exit(1);
  }

  // Connect to MongoDB
  console.log(`[SRV] Connecting to MongoDB...`);
  await connectToMongo();

  // Load accounts
  loadAccounts();
  console.log(`[SRV] User accounts loaded.`);
  console.log(`[SRV] Initialization complete.`);

  server.listen(PORT, '127.0.0.1', () => {
    console.log(`[SRV] Secure WebSocket Server running on wss://127.0.0.1:${PORT}`);
  });
}

// Connection Handling
wss.on('connection', (ws: WebSocket, req: IncomingMessage) => {
  const ipAddress = req.socket.remoteAddress || 'unknown';
  const wsId = ws.toString();
  console.log(`[SRV] New client connected from IP: ${ipAddress}. WS ID: ${wsId}`);

  ws.on('error', (error) => {
    const clientId = clientDataMap.get(ws)?.username || wsId;
    console.error(`[SRV] WebSocket error for: ${clientId}`, error);
    handleDisconnect(ws);
  });

  ws.on('message', (data: RawData) => {
    const clientInfo = clientDataMap.get(ws);
    const clientIdForLog = clientInfo?.username || `WS ${wsId} (IP: ${ipAddress})`;
    const messageString = data.toString();

    let parsedData: BaseMessage;
    try {
      if (messageString.length > MAX_CHUNK_SIZE * 1.5) {
        console.warn(
          `[SRV] Large message (${messageString.length} bytes) received from ${clientIdForLog}. Discarding.`
        );
        sendToClient(ws, { type: ServerMessageType.SYSTEM, content: 'Message too large.' });
        return;
      }
      parsedData = JSON.parse(messageString);
    } catch (error) {
      console.error(`[SRV] Failed to parse JSON from ${clientIdForLog}:`, messageString, error);
      sendToClient(ws, { type: ServerMessageType.SYSTEM, content: 'Invalid JSON format.' });
      return;
    }

    // Rate Limiting Check
    if (rateLimitBlockedUsers.has(ws) && Date.now() < rateLimitBlockedUsers.get(ws)!) {
      return;
    }
    if (!checkRateLimit(ws)) {
      return;
    }

    // Handle PONG
    if (isPongMessage(parsedData)) {
      if (clientInfo) {
        clientInfo.isAlive = true;
      }
      return;
    }

    // Handle Login Attempt
    if (isLoginMessage(parsedData)) {
      if (clientInfo) {
        sendToClient(ws, {
          type: ServerMessageType.SYSTEM,
          content: 'Login failed: Already logged in.',
        });
        return;
      }
      const { username, password } = parsedData;
      if (
        !username ||
        typeof username !== 'string' ||
        username.length < 1 ||
        username.length > 32 ||
        !/^[a-zA-Z0-9_.-]+$/.test(username)
      ) {
        sendToClient(ws, {
          type: ServerMessageType.SYSTEM,
          content: 'Login failed: Invalid username format.',
        });
        return;
      }
      if (
        password === undefined ||
        typeof password !== 'string' ||
        password.length < 1 ||
        password.length > 128
      ) {
        sendToClient(ws, {
          type: ServerMessageType.SYSTEM,
          content: 'Login failed: Invalid password format.',
        });
        return;
      }
      const now = Date.now();
      if (loginBlockedUsers.has(username) && now < loginBlockedUsers.get(username)!) {
        const remainingTime = Math.ceil((loginBlockedUsers.get(username)! - now) / 1000);
        console.log(`[SRV] Login attempt rejected for blocked user: ${username}`);
        sendToClient(ws, {
          type: ServerMessageType.SYSTEM,
          content: `Login failed: Account temporarily blocked. Try again in ${remainingTime} seconds.`,
        });
        return;
      }
      if (loginBlockedUsers.has(username) && now >= loginBlockedUsers.get(username)!) {
        loginBlockedUsers.delete(username);
        console.log(`[SRV] Login block expired for user: ${username}`);
      }
      console.log(`[SRV] Attempting login for username: ${username} from IP: ${ipAddress}`);
      if (clientsByName.has(username)) {
        console.log(`[SRV] Login failed: Username '${username}' already connected.`);
        sendToClient(ws, {
          type: ServerMessageType.SYSTEM,
          content: 'Login failed: User already connected elsewhere.',
        });
        return;
      }
      console.log(`[SRV] Validating credentials for: ${username}`);
      if (validateCredentials(username, password)) {
        console.log(`[SRV] Credentials VALID for ${username}.`);
        loginFailureCounts.delete(username);
        loginBlockedUsers.delete(username);
        const newClientData: ClientData = { username, ipAddress, isAlive: true };
        clientDataMap.set(ws, newClientData);
        clientsByName.set(username, ws);
        console.log(`[SRV] Client data set for ${username}. Stored IP: ${ipAddress}`);
        try {
          sendToClient(ws, { type: ServerMessageType.SYSTEM, content: 'Login successful!' });
          console.log(`[SRV] Login success message sent to ${username}.`);
        } catch (e) {
          console.error(`[SRV] Error sending login success message to ${username}:`, e);
          handleDisconnect(ws);
          return;
        }
        if (serverPublicKeyPem) {
          sendToClient(ws, {
            type: ServerMessageType.SERVER_PUBLIC_KEY,
            publicKey: serverPublicKeyPem,
          });
        } else {
          console.error('[SRV] Server public key not available to send to client!');
        }
        try {
          broadcastUserList();
          console.log(`[SRV] User list broadcast complete after ${username}'s login.`);
        } catch (e) {
          console.error(`[SRV] Error broadcasting user list during ${username}'s login:`, e);
        }
        try {
          startHeartbeat(ws);
          console.log(`[SRV] Heartbeat started for ${username}.`);
        } catch (e) {
          console.error(`[SRV] Error starting heartbeat for ${username}:`, e);
        }
      } else {
        console.log(`[SRV] Login FAILED for: ${username}.`);
        const failureRecord = loginFailureCounts.get(username) || { count: 0, lastAttempt: 0 };
        if (now - failureRecord.lastAttempt > ATTEMPT_WINDOW) {
          failureRecord.count = 0;
        }
        failureRecord.count++;
        failureRecord.lastAttempt = now;
        loginFailureCounts.set(username, failureRecord);
        console.log(
          `[SRV] Login failure count for ${username}: ${failureRecord.count}/${MAX_LOGIN_ATTEMPTS}`
        );
        if (failureRecord.count >= MAX_LOGIN_ATTEMPTS) {
          const unblockTime = now + LOGIN_BLOCK_DURATION;
          loginBlockedUsers.set(username, unblockTime);
          console.log(
            `[SRV] Blocking user ${username} until ${new Date(unblockTime).toISOString()}`
          );
          sendToClient(ws, {
            type: ServerMessageType.SYSTEM,
            content: `Login failed: Too many attempts. Account blocked for ${
              LOGIN_BLOCK_DURATION / 1000
            } seconds.`,
          });
        } else {
          sendToClient(ws, {
            type: ServerMessageType.SYSTEM,
            content: 'Login failed: Invalid username or password.',
          });
        }
      }
      return; // End of login logic
    }

    // Actions Requiring Login
    if (!clientInfo) {
      console.log(`[SRV] Action rejected: Client ${clientIdForLog} is not logged in.`);
      sendToClient(ws, {
        type: ServerMessageType.SYSTEM,
        content: '[SRV]: Action requires login.',
      });
      return;
    }
    const currentUsername = clientInfo.username;
    const currentUserIp = clientInfo.ipAddress;

    // Handle Logout
    if (isLogoutMessage(parsedData)) {
      console.log(`[SRV] Received logout request from ${currentUsername}. WS ID: ${wsId}`);
      handleDisconnect(ws);
      try {
        ws.close(1000, 'User logged out');
      } catch (e) {
        console.error(`[SRV] Error during logout close for ${currentUsername}:`, e);
      }
      return;
    }

    // Handle Share Public Key
    if (isSharePublicKeyMessage(parsedData)) {
      const userPublicKeySpkiBase64 = parsedData.publicKey;
      console.log(`[SRV] Received public key (SPKI Base64) from ${currentUsername}`);
      if (
        userPublicKeySpkiBase64 &&
        typeof userPublicKeySpkiBase64 === 'string' &&
        userPublicKeySpkiBase64.length > 50 &&
        /^[A-Za-z0-9+/=]+$/.test(userPublicKeySpkiBase64)
      ) {
        clientInfo.publicKeySpkiBase64 = userPublicKeySpkiBase64; // Store SPKI Base64
        publicKeys.set(currentUsername, userPublicKeySpkiBase64); // Store in global map
        console.log(`[SRV] User public key stored for ${currentUsername}. Broadcasting...`);
        // Broadcast the key in the same format it was received
        const messageToSend: ReceivePublicKeyServerMessage = {
          type: ServerMessageType.RECEIVE_PUBLIC_KEY,
          username: currentUsername,
          publicKey: userPublicKeySpkiBase64, // Send SPKI Base64
        };
        wss.clients.forEach((otherClient) => {
          if (
            otherClient !== ws &&
            otherClient.readyState === WebSocket.OPEN &&
            clientDataMap.has(otherClient)
          ) {
            sendToClient(otherClient, messageToSend);
          }
        });
        console.log(`[SRV] Finished broadcasting ${currentUsername}'s public key.`);
      } else {
        console.warn(`[SRV] Invalid user public key format received from ${currentUsername}.`);
        sendToClient(ws, {
          type: ServerMessageType.SYSTEM,
          content: '[SRV]: Invalid public key format.',
        });
      }
      return;
    }

    // Handle Request Public Key
    if (isRequestPublicKeyMessage(parsedData)) {
      const targetUsername = parsedData.username;
      console.log(`[SRV] ${currentUsername} requested public key for ${targetUsername}`);
      const targetKeySpkiBase64 = publicKeys.get(targetUsername); // Get SPKI Base64
      if (targetKeySpkiBase64) {
        const messageToSend: ReceivePublicKeyServerMessage = {
          type: ServerMessageType.RECEIVE_PUBLIC_KEY,
          username: targetUsername,
          publicKey: targetKeySpkiBase64, // Send SPKI Base64
        };
        sendToClient(ws, messageToSend);
      } else {
        console.log(
          `[SRV] Key for '${targetUsername}' not found in response to request from ${currentUsername}.`
        );
        sendToClient(ws, {
          type: ServerMessageType.SYSTEM,
          content: `Public key for user '${targetUsername}' not found or user is offline.`,
        });
      }
      return;
    }

    // Handle Intermediary Encrypted Messages
    if (isClientSendMessage(parsedData)) {
      const { recipient, payload } = parsedData;
      const { iv, encryptedKey: encryptedKeyForServerB64, ciphertext: ciphertextB64 } = payload;
      const isBroadcast = !recipient;

      // Decrypt AES key using Server's Private Key
      const aesKeyBuffer = decryptWithServerKey(encryptedKeyForServerB64);
      if (!aesKeyBuffer) {
        console.error(`[SRV] Failed to decrypt AES key from ${currentUsername}. Discarding.`);
        sendToClient(ws, {
          type: ServerMessageType.SYSTEM,
          content: '[SRV Error] Could not process message key.',
        });
        return;
      }

      // Decrypt Message Content using AES Key
      const plaintextMessage = decryptAesGcm(aesKeyBuffer, iv, ciphertextB64);
      if (plaintextMessage === null) {
        console.error(
          `[SRV] Failed to decrypt message content from ${currentUsername}. Discarding.`
        );
        sendToClient(ws, {
          type: ServerMessageType.SYSTEM,
          content: '[SRV Error] Could not decrypt message content.',
        });
        return;
      }

      // Log Message to MongoDB
      const logData: Omit<ChatLogDocument, 'timestamp'> = {
        sender: currentUsername,
        messageContent: plaintextMessage,
        ipAddress: currentUserIp,
        type: isBroadcast ? 'broadcast' : 'private',
        ...(recipient && { recipient: recipient }),
      };
      logToMongo(logData); // Fire-and-forget logging

      // Relay Logic
      if (isBroadcast) {
        console.log(`[SRV] Relaying broadcast message from ${currentUsername}`);
        let relayedCount = 0;
        wss.clients.forEach((targetClient) => {
          if (targetClient !== ws && targetClient.readyState === WebSocket.OPEN) {
            const targetClientData = clientDataMap.get(targetClient);
            if (targetClientData?.publicKeySpkiBase64) {
              const encryptedKeyForTargetB64 = encryptWithRecipientKey(
                targetClientData.publicKeySpkiBase64,
                aesKeyBuffer
              );
              if (encryptedKeyForTargetB64) {
                const messageToSend: ServerReceiveMessage = {
                  type: ServerMessageType.RECEIVE_MESSAGE,
                  sender: currentUsername,
                  isBroadcast: true,
                  payload: {
                    iv: iv,
                    encryptedKey: encryptedKeyForTargetB64,
                    ciphertext: ciphertextB64,
                  },
                };
                sendToClient(targetClient, messageToSend);
                relayedCount++;
              } else {
                console.error(
                  `[SRV] Failed to re-encrypt AES key for broadcast recipient ${targetClientData.username}`
                );
              }
            } else {
              console.warn(
                `[SRV] Cannot relay broadcast to ${
                  targetClientData?.username || 'unknown client'
                }: Missing public key.`
              );
            }
          }
        });
        console.log(`[SRV] Relayed broadcast message to ${relayedCount} other clients.`);
      } else if (recipient) {
        // Private message
        console.log(`[SRV] Relaying private message from ${currentUsername} to ${recipient}`);
        const recipientWs = clientsByName.get(recipient);
        const recipientData = recipientWs ? clientDataMap.get(recipientWs) : null;
        // Use the stored SPKI Base64 key for the recipient
        if (
          recipientWs &&
          recipientWs.readyState === WebSocket.OPEN &&
          recipientData?.publicKeySpkiBase64
        ) {
          const encryptedKeyForRecipientB64 = encryptWithRecipientKey(
            recipientData.publicKeySpkiBase64,
            aesKeyBuffer
          );
          if (encryptedKeyForRecipientB64) {
            const messageToSend: ServerReceiveMessage = {
              type: ServerMessageType.RECEIVE_MESSAGE,
              sender: currentUsername,
              isBroadcast: false,
              payload: {
                iv: iv,
                encryptedKey: encryptedKeyForRecipientB64,
                ciphertext: ciphertextB64,
              },
            };
            sendToClient(recipientWs, messageToSend);
            console.log(`[SRV] Relayed private message to ${recipient}`);
          } else {
            console.error(`[SRV] Failed to re-encrypt AES key for recipient ${recipient}`);
            sendToClient(ws, {
              type: ServerMessageType.SYSTEM,
              content: `[SRV Error] Could not encrypt message for ${recipient}.`,
            });
          }
        } else {
          console.log(
            `[SRV] Private message relay failed: Recipient '${recipient}' offline or missing key.`
          );
          sendToClient(ws, {
            type: ServerMessageType.SYSTEM,
            content: `[SRV]: User '${recipient}' is offline or key unavailable. Message not delivered.`,
          });
        }
      }
      return; // End message handling
    }

    // Handle File Transfers
    if (isFileTransferRequest(parsedData)) {
      const { recipient, fileInfo } = parsedData;
      console.log(`[SRV] Received file transfer request from ${currentUsername} to ${recipient}`);
      if (fileInfo.size > MAX_FILE_SIZE) {
        console.warn(`[SRV] File transfer rejected: File too large.`);
        sendToClient(ws, {
          type: ServerMessageType.SYSTEM,
          content: `File rejected: Exceeds size limit of ${MAX_FILE_SIZE / 1024 / 1024}MB.`,
        });
        return;
      }
      const recipientWs = clientsByName.get(recipient);
      if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
        logToMongo({
          type: 'file_request',
          sender: currentUsername,
          recipient: recipient,
          fileInfo: { name: fileInfo.name, size: fileInfo.size },
          ipAddress: currentUserIp,
        });
        const messageToSend: IncomingFileRequestMessage = {
          type: ServerMessageType.INCOMING_FILE_REQUEST,
          sender: currentUsername,
          fileInfo: fileInfo,
        };
        console.log(`   -> Relaying request to ${recipient}`);
        sendToClient(recipientWs, messageToSend);
      } else {
        console.log(`[SRV] File transfer request failed: Recipient '${recipient}' offline.`);
        sendToClient(ws, {
          type: ServerMessageType.SYSTEM,
          content: `[SRV]: User '${recipient}' is offline. Cannot initiate file transfer.`,
        });
      }
      return;
    }
    if (isFileTransferAccept(parsedData)) {
      const { sender: originalSender, fileInfo } = parsedData;
      console.log(
        `[SRV] Received file transfer acceptance from ${currentUsername} for ${originalSender}'s file: ${fileInfo.name}`
      );
      logToMongo({
        type: 'file_accept',
        sender: currentUsername,
        recipient: originalSender,
        fileInfo: fileInfo,
        ipAddress: currentUserIp,
      });
      const originalSenderWs = clientsByName.get(originalSender);
      if (originalSenderWs && originalSenderWs.readyState === WebSocket.OPEN) {
        const messageToSend: FileAcceptNoticeMessage = {
          type: ServerMessageType.FILE_ACCEPT_NOTICE,
          recipient: currentUsername,
          fileInfo: fileInfo,
        };
        console.log(`   -> Notifying original sender ${originalSender}`);
        sendToClient(originalSenderWs, messageToSend);
      } else {
        console.log(
          `[SRV] File acceptance notice failed: Original sender '${originalSender}' offline.`
        );
        sendToClient(ws, {
          type: ServerMessageType.SYSTEM,
          content: `[SRV]: User '${originalSender}' went offline. File transfer cancelled.`,
        });
      }
      return;
    }
    if (isFileTransferReject(parsedData)) {
      const { sender: originalSender, fileInfo } = parsedData;
      console.log(
        `[SRV] Received file transfer rejection from ${currentUsername} for ${originalSender}'s file: ${fileInfo.name}`
      );
      logToMongo({
        type: 'file_reject',
        sender: currentUsername,
        recipient: originalSender,
        fileInfo: { name: fileInfo.name, size: -1 },
        ipAddress: currentUserIp,
      });
      const originalSenderWs = clientsByName.get(originalSender);
      if (originalSenderWs && originalSenderWs.readyState === WebSocket.OPEN) {
        const messageToSend: FileRejectNoticeMessage = {
          type: ServerMessageType.FILE_REJECT_NOTICE,
          recipient: currentUsername,
          fileInfo: fileInfo,
        };
        console.log(`   -> Notifying original sender ${originalSender}`);
        sendToClient(originalSenderWs, messageToSend);
      } else {
        console.log(
          `[SRV] File rejection notice failed: Original sender '${originalSender}' offline.`
        );
      }
      return;
    }
    if (isFileChunk(parsedData)) {
      const { recipient, fileInfo, chunkData, chunkIndex, isLastChunk } = parsedData;
      if (chunkData.length > MAX_CHUNK_SIZE * 1.4) {
        console.warn(`[SRV] Received oversized chunk from ${currentUsername}. Discarding.`);
        return;
      }
      const recipientWs = clientsByName.get(recipient);
      if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
        const messageToSend: FileChunkReceiveMessage = {
          type: ServerMessageType.FILE_CHUNK_RECEIVE,
          sender: currentUsername,
          fileInfo: fileInfo,
          chunkData: chunkData,
          chunkIndex: chunkIndex,
          isLastChunk: isLastChunk,
        };
        sendToClient(recipientWs, messageToSend);
      } else {
        console.log(`[SRV] File chunk relay failed: Recipient '${recipient}' offline.`);
        sendToClient(ws, {
          type: ServerMessageType.SYSTEM,
          content: `[SRV]: User '${recipient}' went offline. File transfer failed.`,
        });
      }
      return;
    }

    // Unhandled Message Type
    console.warn(
      `[SRV] Unhandled message type: '${(parsedData as any).type}' from: ${currentUsername}`
    );
    sendToClient(ws, {
      type: ServerMessageType.SYSTEM,
      content: '[SRV]: Unrecognized message type.',
    });
  }); // End ws.on('message')

  ws.on('close', (code, reason) => {
    const reasonString = reason ? reason.toString('utf8') : 'N/A';
    const closedClientUsername = clientDataMap.get(ws)?.username;
    console.log(
      `[SRV] Connection closed for: ${
        closedClientUsername || wsId
      }, Code: ${code}, Reason: ${reasonString}`
    );
    handleDisconnect(ws);
  });

  // Send initial welcome message
  try {
    if (ws.readyState === WebSocket.OPEN) {
      sendToClient(ws, {
        type: ServerMessageType.SYSTEM,
        content: 'Welcome to Secure Chat! Please log in.',
      });
    }
  } catch (se) {
    console.error(`[SRV] Failed send welcome message to ${wsId}:`, se);
    handleDisconnect(ws);
    try {
      ws.terminate();
    } catch (e) {}
  }
}); // End wss.on('connection')

// Graceful Shutdown
const shutdown = async () => {
  console.log('[SRV] Shutting down server...');
  heartbeatMap.forEach((intervalId) => clearInterval(intervalId));
  heartbeatMap.clear();
  console.log('[SRV] All heartbeats stopped.');
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      try {
        client.send(
          JSON.stringify({ type: ServerMessageType.SYSTEM, content: 'Server is shutting down.' })
        );
        client.close(1012, 'Server shutting down');
      } catch (e) {
        client.terminate();
      }
    } else {
      client.terminate();
    }
  });
  console.log('[SRV] Notified clients and initiated closing connections.');
  if (db) {
    try {
      await db.client.close();
      console.log('[SRV-DB] MongoDB connection closed gracefully.');
    } catch (err) {
      console.error('[SRV-DB] Error closing MongoDB connection:', err);
    }
  }
  server.close((err) => {
    if (err) {
      console.error('[SRV] Error closing HTTPS server:', err);
      process.exit(1);
    } else {
      console.log('[SRV] HTTPS Server closed gracefully.');
      process.exit(0);
    }
  });
  setTimeout(() => {
    console.error('[SRV] Forcefully shutting down due to timeout.');
    process.exit(1);
  }, 5000);
};
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

// Start the Server
startServer().catch((err) => {
  console.error('[SRV] Failed to start server:', err);
  process.exit(1);
});
