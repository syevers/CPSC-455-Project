import bcrypt from 'bcrypt';
import crypto, { KeyObject } from 'crypto'; // Import crypto module
import { existsSync, readFileSync, writeFileSync } from 'fs';
import type { IncomingMessage } from 'http';
import https from 'https';
import { Collection, Db, MongoClient, Sort } from 'mongodb'; // Import MongoDB types
import path from 'path';
import { fileURLToPath } from 'url';
import { WebSocket, WebSocketServer, type RawData } from 'ws';

// Constants and Setup
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = 8080;
const options = {
  key: readFileSync(path.join(__dirname, '../certs/private.pem')),
  cert: readFileSync(path.join(__dirname, '../certs/public.pem')),
};
const ACCOUNTS_PATH = path.join(__dirname, 'accounts.json');
const RATE_LIMIT = 20; // Messages per second
const RATE_LIMIT_BLOCK_DURATION = 10000; // 10 seconds
const HEARTBEAT_INTERVAL = 30000; // 30 seconds
const SALT_ROUNDS = 10;
const MAX_FILE_SIZE = 10 * 1024 * 1024;
const MAX_CHUNK_SIZE = 64 * 1024;
const MAX_HISTORY_MESSAGES = 200;
const ALL_CHAT_KEY = 'All Chat';

// WebSocket Server Initialization
const server = https.createServer(options);
const wss = new WebSocketServer({ server });

// Brute-Force Protection Constants
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_BLOCK_DURATION = 60 * 1000; // 1 minute
const ATTEMPT_WINDOW = 5 * 60 * 1000; // 5 minutes

// MongoDB Setup
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017';
const MONGODB_DB_NAME = 'secureChat';
const MONGODB_HISTORY_COLLECTION = 'messageHistory';

let db: Db | null = null;
let messageHistoryCollection: Collection<MessageHistoryDocument> | null = null;

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
interface MessageHistoryDocument {
  timestamp: Date;
  sender: string;
  recipient?: string;
  isBroadcast: boolean;
  messageContent: string;
}

// --- Message Types ---
enum ServerMessageType {
  SYSTEM = 'system',
  USER_LIST = 'userList',
  SERVER_PUBLIC_KEY = 'server_public_key',
  RECEIVE_MESSAGE = 'receive_message',
  RECEIVE_PUBLIC_KEY = 'receive_public_key',
  PONG = 'pong',
  PING = 'ping',
  INCOMING_FILE_REQUEST = 'incoming_file_request',
  FILE_ACCEPT_NOTICE = 'file_accept_notice',
  FILE_REJECT_NOTICE = 'file_reject_notice',
  FILE_CHUNK_RECEIVE = 'file_chunk_receive',
  RECEIVE_HISTORY = 'receive_history',
  USER_TYPING = 'user_typing', // User started typing
  USER_STOPPED_TYPING = 'user_stopped_typing', // User stopped typing
}

enum ClientMessageType {
  LOGIN = 'login',
  LOGOUT = 'logout',
  SEND_MESSAGE = 'send_message',
  SHARE_PUBLIC_KEY = 'share_public_key',
  REQUEST_PUBLIC_KEY = 'request_public_key',
  PING = 'ping',
  PONG = 'pong',
  FILE_TRANSFER_REQUEST = 'file_transfer_request',
  FILE_TRANSFER_ACCEPT = 'file_transfer_accept',
  FILE_TRANSFER_REJECT = 'file_transfer_reject',
  FILE_CHUNK = 'file_chunk',
  REQUEST_HISTORY = 'request_history',
  START_TYPING = 'start_typing', // Client indicates typing start
  STOP_TYPING = 'stop_typing', // Client indicates typing stop
}

// --- Message Interfaces ---
interface BaseMessage {
  type: ClientMessageType | ServerMessageType;
}
// Client -> Server
interface LoginMessage extends BaseMessage {
  type: ClientMessageType.LOGIN;
  username: string;
  password?: string;
}
interface LogoutMessage extends BaseMessage {
  type: ClientMessageType.LOGOUT;
  username?: string;
}
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
interface RequestHistoryMessage extends BaseMessage {
  type: ClientMessageType.REQUEST_HISTORY;
}
interface ClientSendMessage extends BaseMessage {
  type: ClientMessageType.SEND_MESSAGE;
  recipient?: string;
  payload: { iv: string; encryptedKey: string; ciphertext: string };
}
interface StartTypingMessage extends BaseMessage {
  type: ClientMessageType.START_TYPING;
  recipient?: string;
} // recipient is null/undefined for broadcast
interface StopTypingMessage extends BaseMessage {
  type: ClientMessageType.STOP_TYPING;
  recipient?: string;
} // recipient is null/undefined for broadcast

// Server -> Client
interface SystemMessage extends BaseMessage {
  type: ServerMessageType.SYSTEM;
  content: string;
}
interface UserListMessage extends BaseMessage {
  type: ServerMessageType.USER_LIST;
  users: string[];
}
interface ServerPublicKeyMessage extends BaseMessage {
  type: ServerMessageType.SERVER_PUBLIC_KEY;
  publicKey: string;
}
interface ServerReceiveMessage extends BaseMessage {
  type: ServerMessageType.RECEIVE_MESSAGE;
  sender: string;
  isBroadcast: boolean;
  payload: { iv: string; encryptedKey: string; ciphertext: string };
}
interface ReceivePublicKeyServerMessage extends BaseMessage {
  type: ServerMessageType.RECEIVE_PUBLIC_KEY;
  username: string;
  publicKey: string;
}
interface PingMessage extends BaseMessage {
  type: ServerMessageType.PING;
}
interface ReceiveHistoryMessage extends BaseMessage {
  type: ServerMessageType.RECEIVE_HISTORY;
  history: PersistedChatHistories;
}
interface UserTypingMessage extends BaseMessage {
  type: ServerMessageType.USER_TYPING;
  sender: string;
  recipient?: string;
} // recipient is null/undefined if typing in broadcast
interface UserStoppedTypingMessage extends BaseMessage {
  type: ServerMessageType.USER_STOPPED_TYPING;
  sender: string;
  recipient?: string;
} // recipient is null/undefined if typing in broadcast

// File Transfer Interfaces (Unchanged)
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

// History Structure Interface (Unchanged)
interface PersistedDisplayMessage {
  type: 'system' | 'chat' | 'my_chat' | 'error';
  content: string;
  sender?: string;
  recipient?: string;
  timestamp?: number;
  isEncrypted?: boolean;
}
interface PersistedChatHistories {
  [peerUsernameOrAllChat: string]: PersistedDisplayMessage[];
}

// --- Type Guards ---
function isLoginMessage(msg: any): msg is LoginMessage {
  return msg?.type === ClientMessageType.LOGIN && typeof msg.username === 'string';
}
function isLogoutMessage(msg: any): msg is LogoutMessage {
  return msg?.type === ClientMessageType.LOGOUT;
}
function isSharePublicKeyMessage(msg: any): msg is SharePublicKeyMessage {
  return msg?.type === ClientMessageType.SHARE_PUBLIC_KEY && typeof msg.publicKey === 'string';
}
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
function isRequestHistoryMessage(msg: any): msg is RequestHistoryMessage {
  return msg?.type === ClientMessageType.REQUEST_HISTORY;
}
// Typing indicator guards
function isStartTypingMessage(msg: any): msg is StartTypingMessage {
  return (
    msg?.type === ClientMessageType.START_TYPING &&
    (msg.recipient === undefined || msg.recipient === null || typeof msg.recipient === 'string')
  );
}
function isStopTypingMessage(msg: any): msg is StopTypingMessage {
  return (
    msg?.type === ClientMessageType.STOP_TYPING &&
    (msg.recipient === undefined || msg.recipient === null || typeof msg.recipient === 'string')
  );
}

// --- Crypto Helper Functions (Unchanged) ---
function decryptWithServerKey(encryptedDataB64: string): Buffer | null {
  if (!serverPrivateKey) {
    console.error('[CRYPTO] Server private key not loaded.');
    return null;
  }
  try {
    const eb = Buffer.from(encryptedDataB64, 'base64');
    return crypto.privateDecrypt(
      {
        key: serverPrivateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      eb
    );
  } catch (e) {
    console.error('[CRYPTO] RSA decryption with server key failed:', e);
    return null;
  }
}
function spkiBase64ToPem(spkiBase64: string): string {
  const pc = spkiBase64.match(/.{1,64}/g)?.join('\n') || '';
  return `-----BEGIN PUBLIC KEY-----\n${pc}\n-----END PUBLIC KEY-----`;
}
function encryptWithRecipientKey(
  recipientPublicKeySpkiBase64: string,
  dataBuffer: Buffer
): string | null {
  try {
    const pkPem = spkiBase64ToPem(recipientPublicKeySpkiBase64);
    const pubKey = crypto.createPublicKey(pkPem);
    const eb = crypto.publicEncrypt(
      { key: pubKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      dataBuffer
    );
    return eb.toString('base64');
  } catch (e) {
    console.error('[CRYPTO] RSA encryption with recipient key failed:', e);
    return null;
  }
}
function decryptAesGcm(aesKey: Buffer, ivB64: string, ciphertextB64: string): string | null {
  try {
    const iv = Buffer.from(ivB64, 'base64');
    const ct = Buffer.from(ciphertextB64, 'base64');
    const atl = 16;
    if (ct.length < atl) {
      throw new Error('Invalid ciphertext length for GCM.');
    }
    const ep = ct.subarray(0, ct.length - atl);
    const at = ct.subarray(ct.length - atl);
    const d = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
    d.setAuthTag(at);
    let dec = d.update(ep, undefined, 'utf8');
    dec += d.final('utf8');
    return dec;
  } catch (e) {
    console.error('[CRYPTO] AES-GCM decryption failed:', e);
    return null;
  }
}

// --- Helper Functions (Account management unchanged) ---
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

// --- Database Interaction Functions (Unchanged) ---
async function saveMessageToHistory(
  messageData: Omit<MessageHistoryDocument, 'timestamp'>
): Promise<void> {
  if (!messageHistoryCollection) {
    console.error('[SRV-DB] History collection not available. Cannot save message.');
    return;
  }
  const doc: MessageHistoryDocument = { ...messageData, timestamp: new Date() };
  try {
    const r = await messageHistoryCollection.insertOne(doc);
    if (!r.acknowledged) {
      console.warn('[SRV-DB] DB insert not acknowledged for sender:', messageData.sender);
    }
  } catch (e) {
    console.error('[SRV-DB] Error saving message to DB:', e, 'Data:', doc);
  }
}
async function fetchUserHistory(username: string): Promise<PersistedChatHistories> {
  const history: PersistedChatHistories = { [ALL_CHAT_KEY]: [] };
  if (!messageHistoryCollection) {
    console.error(
      `[SRV-DB] History collection not available. Cannot fetch history for ${username}.`
    );
    return history;
  }
  try {
    const query = { $or: [{ sender: username }, { recipient: username }, { isBroadcast: true }] };
    const sort: Sort = { timestamp: -1 };
    const dbMessages = await messageHistoryCollection
      .find(query)
      .sort(sort)
      .limit(MAX_HISTORY_MESSAGES)
      .toArray();
    dbMessages.reverse().forEach((msg) => {
      let messageType: PersistedDisplayMessage['type'] = 'chat';
      if (msg.sender === username) {
        messageType = 'my_chat';
      }
      const displayMsg: PersistedDisplayMessage = {
        type: messageType,
        content: msg.messageContent,
        sender: msg.sender,
        recipient: msg.sender === username ? msg.recipient : undefined,
        timestamp: msg.timestamp.getTime(),
        isEncrypted: true,
      };
      let peerKey: string;
      if (msg.isBroadcast) {
        peerKey = ALL_CHAT_KEY;
      } else if (msg.sender === username) {
        peerKey = msg.recipient!;
      } else {
        peerKey = msg.sender;
      }
      if (!history[peerKey]) {
        history[peerKey] = [];
      }
      history[peerKey].push(displayMsg);
    });
    if (!history[ALL_CHAT_KEY]) {
      history[ALL_CHAT_KEY] = [];
    }
    console.log(`[SRV-DB] Fetched ${dbMessages.length} history messages for ${username}.`);
    return history;
  } catch (e) {
    console.error(`[SRV-DB] Error fetching history for ${username}:`, e);
    return history;
  }
}

// --- Broadcast/Send Functions (Unchanged) ---
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

// --- Connection Management (Unchanged) ---
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
  const cd = clientDataMap.get(ws);
  const cid = cd?.username || ws.toString();
  if (!cd) {
    console.error(`[SRV] Cannot start heartbeat for ${cid}: client data not found.`);
    return;
  }
  console.log(`[SRV] Starting heartbeat for ${cid}`);
  cd.isAlive = true;
  const intId = setInterval(() => {
    const ccd = clientDataMap.get(ws);
    const ccid = ccd?.username || ws.toString();
    if (!ccd) {
      console.warn(`[SRV] Heartbeat: Client data missing (WS ${ws.toString()}), stopping.`);
      if (heartbeatMap.has(ws)) {
        clearInterval(heartbeatMap.get(ws)!);
        heartbeatMap.delete(ws);
      }
      return;
    }
    if (ccd.isAlive === false) {
      console.log(`[SRV] Heartbeat failed (no pong) for ${ccid}. Terminating.`);
      handleDisconnect(ws);
      ws.terminate();
      return;
    }
    ccd.isAlive = false;
    try {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: ServerMessageType.PING }));
      } else {
        console.log(`[SRV] Heartbeat: WS not open during ping for ${ccid}, cleaning up.`);
        handleDisconnect(ws);
      }
    } catch (se) {
      console.error(`[SRV] Failed send PING to ${ccid}:`, se);
      handleDisconnect(ws);
      ws.terminate();
    }
  }, HEARTBEAT_INTERVAL);
  heartbeatMap.set(ws, intId);
}
function stopHeartbeat(ws: WebSocket) {
  if (heartbeatMap.has(ws)) {
    clearInterval(heartbeatMap.get(ws)!);
    heartbeatMap.delete(ws);
  }
}

// --- MongoDB Connection Function (Unchanged) ---
async function connectToMongo() {
  try {
    const client = new MongoClient(MONGODB_URI);
    await client.connect();
    db = client.db(MONGODB_DB_NAME);
    messageHistoryCollection = db.collection(MONGODB_HISTORY_COLLECTION);
    await messageHistoryCollection.createIndex({ timestamp: -1 });
    await messageHistoryCollection.createIndex({ sender: 1 });
    await messageHistoryCollection.createIndex({ recipient: 1 });
    await messageHistoryCollection.createIndex({ isBroadcast: 1 });
    await messageHistoryCollection.createIndex({
      sender: 1,
      recipient: 1,
      isBroadcast: 1,
      timestamp: -1,
    });
    console.log(
      `[SRV-DB] Successfully connected to MongoDB: ${MONGODB_DB_NAME}/${MONGODB_HISTORY_COLLECTION}`
    );
  } catch (e) {
    console.error('[SRV-DB] Failed to connect to MongoDB:', e);
    process.exit(1);
  }
}

// --- State Management (Unchanged) ---
interface ClientData {
  username: string;
  ipAddress: string;
  publicKeySpkiBase64?: string;
  isAlive?: boolean;
}
const clientDataMap = new Map<WebSocket, ClientData>();
const clientsByName = new Map<string, WebSocket>();
const publicKeys = new Map<string, string>();
const heartbeatMap = new Map<WebSocket, NodeJS.Timeout>();
const messageTimestamps = new Map<WebSocket, number[]>();
const rateLimitBlockedUsers = new Map<WebSocket, number>();
const loginFailureCounts = new Map<string, { count: number; lastAttempt: number }>();
const loginBlockedUsers = new Map<string, number>();

// --- Main Server Startup Logic (Unchanged) ---
async function startServer() {
  console.log(`[SRV] Initializing...`);
  try {
    const privPath = path.join(__dirname, '../certs/server_private.pem');
    const pubPath = path.join(__dirname, '../certs/server_public.pem');
    if (!existsSync(privPath) || !existsSync(pubPath)) {
      console.error(`[FATAL] Server key pair not found in certs/ directory.`);
      process.exit(1);
    }
    const privPem = readFileSync(privPath, 'utf8');
    serverPublicKeyPem = readFileSync(pubPath, 'utf8');
    serverPrivateKey = crypto.createPrivateKey(privPem);
    console.log('[SRV] Server key pair loaded successfully.');
  } catch (e) {
    console.error('[SRV] Failed to load server key pair:', e);
    process.exit(1);
  }
  console.log(`[SRV] Connecting to MongoDB...`);
  await connectToMongo();
  loadAccounts();
  console.log(`[SRV] User accounts loaded.`);
  console.log(`[SRV] Initialization complete.`);
  server.listen(PORT, '127.0.0.1', () => {
    console.log(`[SRV] Secure WebSocket Server running on wss://127.0.0.1:${PORT}`);
  });
}

// --- Connection Handling ---
wss.on('connection', (ws: WebSocket, req: IncomingMessage) => {
  const ipAddress = req.socket.remoteAddress || 'unknown';
  const wsId = ws.toString();
  console.log(`[SRV] New client connected from IP: ${ipAddress}. WS ID: ${wsId}`);

  ws.on('error', (error) => {
    const clientId = clientDataMap.get(ws)?.username || wsId;
    console.error(`[SRV] WebSocket error for: ${clientId}`, error);
    handleDisconnect(ws);
  });

  // --- WebSocket Message Handler (MODIFIED) ---
  ws.on('message', async (data: RawData) => {
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

    // Handle Login Attempt (Unchanged logic)
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
        const rt = Math.ceil((loginBlockedUsers.get(username)! - now) / 1000);
        console.log(`[SRV] Login attempt rejected for blocked user: ${username}`);
        sendToClient(ws, {
          type: ServerMessageType.SYSTEM,
          content: `Login failed: Account temporarily blocked. Try again in ${rt} seconds.`,
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
          if (serverPublicKeyPem) {
            sendToClient(ws, {
              type: ServerMessageType.SERVER_PUBLIC_KEY,
              publicKey: serverPublicKeyPem,
            });
          } else {
            console.error('[SRV] Server public key not available to send to client!');
          }
        } catch (e) {
          console.error(`[SRV] Error sending login success/key to ${username}:`, e);
          handleDisconnect(ws);
          return;
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
        const fr = loginFailureCounts.get(username) || { count: 0, lastAttempt: 0 };
        if (now - fr.lastAttempt > ATTEMPT_WINDOW) {
          fr.count = 0;
        }
        fr.count++;
        fr.lastAttempt = now;
        loginFailureCounts.set(username, fr);
        console.log(`[SRV] Login failure count for ${username}: ${fr.count}/${MAX_LOGIN_ATTEMPTS}`);
        if (fr.count >= MAX_LOGIN_ATTEMPTS) {
          const ut = now + LOGIN_BLOCK_DURATION;
          loginBlockedUsers.set(username, ut);
          console.log(`[SRV] Blocking user ${username} until ${new Date(ut).toISOString()}`);
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

    // --- Actions Requiring Login ---
    if (!clientInfo) {
      console.log(`[SRV] Action rejected: Client ${clientIdForLog} is not logged in.`);
      sendToClient(ws, {
        type: ServerMessageType.SYSTEM,
        content: '[SRV]: Action requires login.',
      });
      return;
    }
    const currentUsername = clientInfo.username;
    // const currentUserIp = clientInfo.ipAddress; // Available if needed

    // Handle Logout (Unchanged)
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

    // Handle Share Public Key (Unchanged)
    if (isSharePublicKeyMessage(parsedData)) {
      const pk = parsedData.publicKey;
      console.log(`[SRV] Received public key (SPKI Base64) from ${currentUsername}`);
      if (pk && typeof pk === 'string' && pk.length > 50 && /^[A-Za-z0-9+/=]+$/.test(pk)) {
        clientInfo.publicKeySpkiBase64 = pk;
        publicKeys.set(currentUsername, pk);
        console.log(`[SRV] User public key stored for ${currentUsername}. Broadcasting...`);
        const msg: ReceivePublicKeyServerMessage = {
          type: ServerMessageType.RECEIVE_PUBLIC_KEY,
          username: currentUsername,
          publicKey: pk,
        };
        wss.clients.forEach((oc) => {
          if (oc !== ws && oc.readyState === WebSocket.OPEN && clientDataMap.has(oc)) {
            sendToClient(oc, msg);
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

    // Handle Request Public Key (Unchanged)
    if (isRequestPublicKeyMessage(parsedData)) {
      const tu = parsedData.username;
      console.log(`[SRV] ${currentUsername} requested public key for ${tu}`);
      const tk = publicKeys.get(tu);
      if (tk) {
        const msg: ReceivePublicKeyServerMessage = {
          type: ServerMessageType.RECEIVE_PUBLIC_KEY,
          username: tu,
          publicKey: tk,
        };
        sendToClient(ws, msg);
      } else {
        console.log(
          `[SRV] Key for '${tu}' not found in response to request from ${currentUsername}.`
        );
        sendToClient(ws, {
          type: ServerMessageType.SYSTEM,
          content: `Public key for user '${tu}' not found or user is offline.`,
        });
      }
      return;
    }

    // Handle Request History (Unchanged)
    if (isRequestHistoryMessage(parsedData)) {
      console.log(`[SRV] Received history request from ${currentUsername}`);
      try {
        const uh = await fetchUserHistory(currentUsername);
        const hm: ReceiveHistoryMessage = { type: ServerMessageType.RECEIVE_HISTORY, history: uh };
        sendToClient(ws, hm);
        console.log(`[SRV] Sent history to ${currentUsername}`);
      } catch (e) {
        console.error(`[SRV] Error preparing/sending history for ${currentUsername}:`, e);
        sendToClient(ws, {
          type: ServerMessageType.SYSTEM,
          content: '[SRV Error] Could not retrieve chat history.',
        });
      }
      return;
    }

    // Handle Intermediary Encrypted Messages (Unchanged logic, includes saving)
    if (isClientSendMessage(parsedData)) {
      const { recipient, payload } = parsedData;
      const { iv, encryptedKey: ekfsb64, ciphertext: ctb64 } = payload;
      const isB = !recipient;
      const akb = decryptWithServerKey(ekfsb64);
      if (!akb) {
        console.error(`[SRV] Failed to decrypt AES key from ${currentUsername}. Discarding.`);
        sendToClient(ws, {
          type: ServerMessageType.SYSTEM,
          content: '[SRV Error] Could not process message key.',
        });
        return;
      }
      const ptm = decryptAesGcm(akb, iv, ctb64);
      if (ptm === null) {
        console.error(
          `[SRV] Failed to decrypt message content from ${currentUsername}. Discarding.`
        );
        sendToClient(ws, {
          type: ServerMessageType.SYSTEM,
          content: '[SRV Error] Could not decrypt message content.',
        });
        return;
      }
      const mts: Omit<MessageHistoryDocument, 'timestamp'> = {
        sender: currentUsername,
        messageContent: ptm,
        isBroadcast: isB,
        ...(recipient && { recipient: recipient }),
      };
      await saveMessageToHistory(mts);
      if (isB) {
        console.log(`[SRV] Relaying broadcast message from ${currentUsername}`);
        let rc = 0;
        wss.clients.forEach((tc) => {
          if (tc !== ws && tc.readyState === WebSocket.OPEN) {
            const tcd = clientDataMap.get(tc);
            if (tcd?.publicKeySpkiBase64) {
              const ekftb64 = encryptWithRecipientKey(tcd.publicKeySpkiBase64, akb);
              if (ekftb64) {
                const mts: ServerReceiveMessage = {
                  type: ServerMessageType.RECEIVE_MESSAGE,
                  sender: currentUsername,
                  isBroadcast: true,
                  payload: { iv: iv, encryptedKey: ekftb64, ciphertext: ctb64 },
                };
                sendToClient(tc, mts);
                rc++;
              } else {
                console.error(
                  `[SRV] Failed to re-encrypt AES key for broadcast recipient ${tcd.username}`
                );
              }
            } else {
              console.warn(
                `[SRV] Cannot relay broadcast to ${
                  tcd?.username || 'unknown client'
                }: Missing public key or not logged in.`
              );
            }
          }
        });
        console.log(`[SRV] Relayed broadcast message to ${rc} other clients.`);
      } else if (recipient) {
        console.log(`[SRV] Relaying private message from ${currentUsername} to ${recipient}`);
        const rws = clientsByName.get(recipient);
        const rd = rws ? clientDataMap.get(rws) : null;
        if (rws && rws.readyState === WebSocket.OPEN && rd?.publicKeySpkiBase64) {
          const ekfrb64 = encryptWithRecipientKey(rd.publicKeySpkiBase64, akb);
          if (ekfrb64) {
            const mts: ServerReceiveMessage = {
              type: ServerMessageType.RECEIVE_MESSAGE,
              sender: currentUsername,
              isBroadcast: false,
              payload: { iv: iv, encryptedKey: ekfrb64, ciphertext: ctb64 },
            };
            sendToClient(rws, mts);
            console.log(`[SRV] Relayed private message to ${recipient}`);
          } else {
            console.error(`[SRV] Failed to re-encrypt AES key for recipient ${recipient}`);
            sendToClient(ws, {
              type: ServerMessageType.SYSTEM,
              content: `[SRV Error] Could not encrypt message for ${recipient}. Message not delivered.`,
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
      return;
    }

    // --- Handle Typing Indicators ---
    if (isStartTypingMessage(parsedData) || isStopTypingMessage(parsedData)) {
      const { recipient } = parsedData;
      const isBroadcast = !recipient;
      const messageType = isStartTypingMessage(parsedData)
        ? ServerMessageType.USER_TYPING
        : ServerMessageType.USER_STOPPED_TYPING;

      const messageToSend: UserTypingMessage | UserStoppedTypingMessage = {
        type: messageType,
        sender: currentUsername,
        // Include recipient only if it was a private typing indicator
        ...(recipient && { recipient: recipient }),
      };

      if (isBroadcast) {
        // Broadcast to everyone EXCEPT the sender
        // console.log(`[SRV] Broadcasting ${messageType} from ${currentUsername}`); // Can be noisy
        wss.clients.forEach((client) => {
          if (client !== ws && client.readyState === WebSocket.OPEN && clientDataMap.has(client)) {
            sendToClient(client, messageToSend);
          }
        });
      } else if (recipient) {
        // Send only to the specified recipient
        const recipientWs = clientsByName.get(recipient);
        if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
          // console.log(`[SRV] Sending ${messageType} from ${currentUsername} to ${recipient}`); // Can be noisy
          sendToClient(recipientWs, messageToSend);
        } else {
          // console.log(`[SRV] Typing indicator not sent: Recipient ${recipient} offline.`); // Optional log
        }
      }
      return; // End typing indicator handling
    }

    // Handle File Transfers (Unchanged logic)
    if (isFileTransferRequest(parsedData)) {
      const { recipient, fileInfo } = parsedData;
      console.log(`[SRV] Received file transfer request from ${currentUsername} to ${recipient}`);
      if (fileInfo.size > MAX_FILE_SIZE) {
        console.warn(`[SRV] File transfer rejected: File too large (${fileInfo.size} bytes).`);
        sendToClient(ws, {
          type: ServerMessageType.SYSTEM,
          content: `File rejected: Exceeds size limit of ${MAX_FILE_SIZE / 1024 / 1024}MB.`,
        });
        return;
      }
      const rws = clientsByName.get(recipient);
      if (rws && rws.readyState === WebSocket.OPEN) {
        const mts: IncomingFileRequestMessage = {
          type: ServerMessageType.INCOMING_FILE_REQUEST,
          sender: currentUsername,
          fileInfo: fileInfo,
        };
        console.log(`   -> Relaying request to ${recipient}`);
        sendToClient(rws, mts);
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
      const { sender: os, fileInfo } = parsedData;
      console.log(
        `[SRV] Received file transfer acceptance from ${currentUsername} for ${os}'s file: ${fileInfo.name}`
      );
      const osws = clientsByName.get(os);
      if (osws && osws.readyState === WebSocket.OPEN) {
        const mts: FileAcceptNoticeMessage = {
          type: ServerMessageType.FILE_ACCEPT_NOTICE,
          recipient: currentUsername,
          fileInfo: fileInfo,
        };
        console.log(`   -> Notifying original sender ${os}`);
        sendToClient(osws, mts);
      } else {
        console.log(`[SRV] File acceptance notice failed: Original sender '${os}' offline.`);
        sendToClient(ws, {
          type: ServerMessageType.SYSTEM,
          content: `[SRV]: User '${os}' went offline. File transfer cancelled.`,
        });
      }
      return;
    }
    if (isFileTransferReject(parsedData)) {
      const { sender: os, fileInfo } = parsedData;
      console.log(
        `[SRV] Received file transfer rejection from ${currentUsername} for ${os}'s file: ${fileInfo.name}`
      );
      const osws = clientsByName.get(os);
      if (osws && osws.readyState === WebSocket.OPEN) {
        const mts: FileRejectNoticeMessage = {
          type: ServerMessageType.FILE_REJECT_NOTICE,
          recipient: currentUsername,
          fileInfo: fileInfo,
        };
        console.log(`   -> Notifying original sender ${os}`);
        sendToClient(osws, mts);
      } else {
        console.log(`[SRV] File rejection notice failed: Original sender '${os}' offline.`);
      }
      return;
    }
    if (isFileChunk(parsedData)) {
      const { recipient, fileInfo, chunkData, chunkIndex, isLastChunk } = parsedData;
      if (chunkData.length > MAX_CHUNK_SIZE * 1.4) {
        console.warn(
          `[SRV] Received oversized chunk from ${currentUsername} for ${recipient}. Discarding.`
        );
        return;
      }
      const rws = clientsByName.get(recipient);
      if (rws && rws.readyState === WebSocket.OPEN) {
        const mts: FileChunkReceiveMessage = {
          type: ServerMessageType.FILE_CHUNK_RECEIVE,
          sender: currentUsername,
          fileInfo: fileInfo,
          chunkData: chunkData,
          chunkIndex: chunkIndex,
          isLastChunk: isLastChunk,
        };
        sendToClient(rws, mts);
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

// --- Graceful Shutdown (Unchanged) ---
const shutdown = async () => {
  console.log('[SRV] Shutting down server...');
  heartbeatMap.forEach((intId) => clearInterval(intId));
  heartbeatMap.clear();
  console.log('[SRV] All heartbeats stopped.');
  wss.clients.forEach((c) => {
    if (c.readyState === WebSocket.OPEN) {
      try {
        c.send(
          JSON.stringify({ type: ServerMessageType.SYSTEM, content: 'Server is shutting down.' })
        );
        c.close(1012, 'Server shutting down');
      } catch (e) {
        c.terminate();
      }
    } else {
      c.terminate();
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
