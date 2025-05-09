import bcrypt from 'bcrypt';
import crypto, { KeyObject } from 'crypto';
import admin from 'firebase-admin';
import type { FieldValue, Timestamp } from 'firebase-admin/firestore';
import { existsSync, readFileSync } from 'fs';
import type { IncomingMessage, ServerResponse } from 'http';
import http from 'http';
import path from 'path';
import { WebSocket, WebSocketServer, type RawData } from 'ws';

const RENDER_DATA_PATH = '/var/render/data';
const SERVER_KEY_PATH_PRIVATE = path.join(RENDER_DATA_PATH, 'certs/server_private.pem');
const SERVER_KEY_PATH_PUBLIC = path.join(RENDER_DATA_PATH, 'certs/server_public.pem');
const FIREBASE_KEY_PATH_ON_DISK = path.join(RENDER_DATA_PATH, 'firebase-key.json');

const PORT = process.env.PORT || 8080;

const RATE_LIMIT = 20;
const RATE_LIMIT_BLOCK_DURATION = 10000;
const HEARTBEAT_INTERVAL = 30000;
const SALT_ROUNDS = 10;
const MAX_FILE_SIZE = 10 * 1024 * 1024;
const MAX_CHUNK_SIZE = 64 * 1024;
const MAX_HISTORY_MESSAGES = 200;
const ALL_CHAT_KEY = 'All Chat';
const FIRESTORE_HISTORY_COLLECTION = 'chatlogs';
const FIRESTORE_USERS_COLLECTION = 'users';

let firestore: admin.firestore.Firestore | null = null;
let serviceAccount: any;

try {
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    console.log('[SRV-DB] Initializing Firebase using FIREBASE_SERVICE_ACCOUNT env var.');
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    if (!serviceAccount || typeof serviceAccount !== 'object') {
      throw new Error('Parsed FIREBASE_SERVICE_ACCOUNT is not a valid object.');
    }
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
  } else {
    throw new Error(
      'Firebase credentials not configured. Set FIREBASE_SERVICE_ACCOUNT (with JSON content) environment variable on Render.'
    );
  }

  firestore = admin.firestore();
  if (firestore) {
    console.log('[SRV-DB] Firestore instance obtained successfully.');
  } else {
    throw new Error('Failed to get Firestore instance from initialized app.');
  }
  console.log('[SRV-DB] Firebase Admin SDK initialized successfully for Firestore.');
} catch (error: any) {
  console.error('[SRV-DB] FATAL: Failed to initialize Firebase Admin SDK:', error.message);
  if (process.env.FIREBASE_SERVICE_ACCOUNT && typeof serviceAccount === 'undefined') {
    console.error(
      '[SRV-DB] Failed parsing FIREBASE_SERVICE_ACCOUNT environment variable JSON content.'
    );
  } else if (typeof serviceAccount !== 'undefined') {
    console.error(
      '[SRV-DB] Service Account Object (if parsed from FIREBASE_SERVICE_ACCOUNT):',
      serviceAccount
    );
  }
  process.exit(1);
}


// Add a request listener to handle GET/HEAD / for health checks 
const server = http.createServer((req: IncomingMessage, res: ServerResponse) => {
  if (req.url === '/' && (req.method === 'GET' || req.method === 'HEAD')) {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    // End response: send body only for GET, none for HEAD
    res.end('Server is running and ready for WebSocket connections.\n');
  }
  // Check if it's NOT a WebSocket upgrade request
  else if (!req.headers.upgrade || req.headers.upgrade.toLowerCase() !== 'websocket') {
    // It's some other HTTP request, respond with 404 Not Found
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found\n');
  }
});

const wss = new WebSocketServer({ server });

const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_BLOCK_DURATION = 60 * 1000;
const ATTEMPT_WINDOW = 5 * 60 * 1000;

let serverPrivateKey: KeyObject | null = null;
let serverPublicKeyPem: string | null = null;

interface UserAccount {
  username: string;
  passwordHash: string;
}

interface MessageHistoryDocument {
  timestamp: FieldValue;
  sender: string;
  recipient?: string;
  isBroadcast: boolean;
  messageContent: string;
}
interface MessageHistoryData extends Omit<MessageHistoryDocument, 'timestamp'> {
  timestamp: Timestamp;
}

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
  USER_TYPING = 'user_typing',
  USER_STOPPED_TYPING = 'user_stopped_typing',
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
  START_TYPING = 'start_typing',
  STOP_TYPING = 'stop_typing',
}

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
}
interface StopTypingMessage extends BaseMessage {
  type: ClientMessageType.STOP_TYPING;
  recipient?: string;
}
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
interface ReceiveHistoryMessage extends BaseMessage {
  type: ServerMessageType.RECEIVE_HISTORY;
  history: PersistedChatHistories;
}
interface UserTypingMessage extends BaseMessage {
  type: ServerMessageType.USER_TYPING;
  sender: string;
  recipient?: string;
}
interface UserStoppedTypingMessage extends BaseMessage {
  type: ServerMessageType.USER_STOPPED_TYPING;
  sender: string;
  recipient?: string;
}
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

async function addNewUserToFirestore(username: string, password?: string): Promise<boolean> {
  if (!firestore) {
    console.error('[SRV-DB] Firestore not initialized. Cannot add user.');
    return false;
  }
  if (!password) {
    console.log('[SRV] No password provided for new user:', username);
    return false;
  }
  try {
    const usersCollection = firestore.collection(FIRESTORE_USERS_COLLECTION);
    const querySnapshot = await usersCollection
      .where('usernameLower', '==', username.toLowerCase())
      .limit(1)
      .get();

    if (!querySnapshot.empty) {
      console.log('[SRV-DB] User already exists (checked case-insensitively):', username);
      return false;
    }

    const passwordHash = bcrypt.hashSync(password, SALT_ROUNDS);
    await usersCollection.add({
      username: username,
      usernameLower: username.toLowerCase(),
      passwordHash: passwordHash,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    console.log('[SRV-DB] New user added successfully to Firestore:', username);
    return true;
  } catch (e) {
    console.error('[SRV-DB] Error adding new user to Firestore:', e);
    return false;
  }
}

async function validateCredentialsWithFirestore(
  username: string,
  password?: string
): Promise<boolean> {
  if (!firestore) {
    console.error('[SRV-DB] Firestore not initialized. Cannot validate credentials.');
    return false;
  }
  if (!password) {
    console.log(`[SRV] Login fail: Missing password for ${username}`);
    return false;
  }

  try {
    const usersCollection = firestore.collection(FIRESTORE_USERS_COLLECTION);
    const querySnapshot = await usersCollection
      .where('usernameLower', '==', username.toLowerCase())
      .limit(1)
      .get();

    if (querySnapshot.empty) {
      console.log('[SRV-DB] User not found, creating in Firestore:', username);
      return await addNewUserToFirestore(username, password);
    } else {
      const userDoc = querySnapshot.docs[0];
      const userData = userDoc.data() as UserAccount;

      if (!userData.passwordHash) {
        console.log(`[SRV] Login fail: Missing password hash for ${username} in Firestore.`);
        return false;
      }

      const isValid = bcrypt.compareSync(password, userData.passwordHash);
      if (!isValid) {
        console.log(`[SRV] Login fail: Invalid password for ${username} (Firestore).`);
      }
      return isValid;
    }
  } catch (e) {
    console.error('[SRV-DB] Error during credential validation with Firestore:', e);
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

async function saveMessageToHistory(
  messageData: Omit<MessageHistoryDocument, 'timestamp'>
): Promise<void> {
  if (!firestore) {
    console.error('[SRV-DB] Firestore not initialized. Cannot save message.');
    return;
  }
  try {
    const historyCollection = firestore.collection(FIRESTORE_HISTORY_COLLECTION);
    await historyCollection.add({
      ...messageData,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
    });
  } catch (error) {
    console.error('[SRV-DB] Error saving message to Firestore:', error, 'Data:', messageData);
  }
}

async function fetchUserHistory(username: string): Promise<PersistedChatHistories> {
  const history: PersistedChatHistories = { [ALL_CHAT_KEY]: [] };
  if (!firestore) {
    console.error(`[SRV-DB] Firestore not initialized. Cannot fetch history for ${username}.`);
    return history;
  }
  const historyCollection = firestore.collection(FIRESTORE_HISTORY_COLLECTION);

  try {
    const sentQuery = historyCollection
      .where('sender', '==', username)
      .orderBy('timestamp', 'desc')
      .limit(MAX_HISTORY_MESSAGES);

    const receivedQuery = historyCollection
      .where('recipient', '==', username)
      .orderBy('timestamp', 'desc')
      .limit(MAX_HISTORY_MESSAGES);

    const broadcastQuery = historyCollection
      .where('isBroadcast', '==', true)
      .orderBy('timestamp', 'desc')
      .limit(MAX_HISTORY_MESSAGES);

    const [sentSnapshot, receivedSnapshot, broadcastSnapshot] = await Promise.all([
      sentQuery.get(),
      receivedQuery.get(),
      broadcastQuery.get(),
    ]);

    const combinedMessages = new Map<string, MessageHistoryData>();

    sentSnapshot.forEach((doc) => combinedMessages.set(doc.id, doc.data() as MessageHistoryData));
    receivedSnapshot.forEach((doc) =>
      combinedMessages.set(doc.id, doc.data() as MessageHistoryData)
    );
    broadcastSnapshot.forEach((doc) =>
      combinedMessages.set(doc.id, doc.data() as MessageHistoryData)
    );

    const validMessages = Array.from(combinedMessages.values()).filter((msg) => msg.timestamp);

    validMessages.sort((a, b) => b.timestamp.toMillis() - a.timestamp.toMillis());
    const limitedMessages = validMessages.slice(0, MAX_HISTORY_MESSAGES);
    limitedMessages.reverse();

    limitedMessages.forEach((msg) => {
      if (!msg.timestamp || typeof msg.timestamp.toMillis !== 'function') {
        console.warn('[SRV-DB] Skipping message with invalid timestamp:', msg);
        return;
      }

      let messageType: PersistedDisplayMessage['type'] = 'chat';
      if (msg.sender === username) messageType = 'my_chat';

      const displayMsg: PersistedDisplayMessage = {
        type: messageType,
        content: msg.messageContent,
        sender: msg.sender,
        recipient: msg.sender === username ? msg.recipient : undefined,
        timestamp: msg.timestamp.toMillis(),
        isEncrypted: true,
      };

      let peerKey: string;
      if (msg.isBroadcast) peerKey = ALL_CHAT_KEY;
      else if (msg.sender === username) peerKey = msg.recipient!;
      else peerKey = msg.sender;

      if (!history[peerKey]) history[peerKey] = [];
      history[peerKey].push(displayMsg);
    });

    if (!history[ALL_CHAT_KEY]) history[ALL_CHAT_KEY] = [];
    console.log(
      `[SRV-DB] Processed ${limitedMessages.length} history messages for ${username} from Firestore.`
    );
  } catch (error) {
    console.error(`[SRV-DB] Error fetching history for ${username} from Firestore:`, error);
    if ((error as any).code === 5 || (error as any).code === 'failed-precondition') {
      console.error(
        "[SRV-DB] Hint: Firestore query failed. This might be due to missing indexes or the collection '" +
          FIRESTORE_HISTORY_COLLECTION +
          "' not existing. Check the Firestore console in your Firebase project to create the necessary composite indexes based on the 'where' and 'orderBy' clauses used in fetchUserHistory (sender+timestamp, recipient+timestamp, isBroadcast+timestamp). Also ensure the collection exists or the first write succeeds."
      );
    }
  }
  return history;
}

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

async function startServer() {
  console.log(`[SRV] Initializing...`);
  try {
    const privKeyPem = process.env.APP_PRIVATE_KEY;
    serverPublicKeyPem = process.env.APP_PUBLIC_KEY ?? null;

    if (!privKeyPem || !serverPublicKeyPem) {
      throw new Error(
        'Server key pair not found in environment variables (APP_PRIVATE_KEY, APP_PUBLIC_KEY).'
      );
    }

    serverPrivateKey = crypto.createPrivateKey(privKeyPem);
    console.log('[SRV] Server key pair loaded successfully from environment variables.');
  } catch (error: any) {
    console.error(
      '[SRV] Failed to load server key pair from environment variables:',
      error.message
    );
    process.exit(1);
  }

  console.log(`[SRV] User accounts will be handled by Firestore.`);
  console.log(`[SRV] Initialization complete.`);

  const numericPort = typeof PORT === 'string' ? parseInt(PORT, 10) : PORT;
  if (isNaN(numericPort)) {
    console.error(`[SRV] Invalid PORT specified: ${PORT}. Using default 8080.`);
  }
  const portToListen = isNaN(numericPort) ? 8080 : numericPort;

  server.listen(portToListen, '0.0.0.0', () => {
    console.log(`[SRV] HTTP WebSocket Server running on http://0.0.0.0:${portToListen}`);
  });
}

wss.on('connection', (ws: WebSocket, req: IncomingMessage) => {
  const ipAddress = req.socket.remoteAddress || 'unknown';
  const wsId = ws.toString();
  console.log(`[SRV] New client connected from IP: ${ipAddress}. WS ID: ${wsId}`);

  ws.on('error', (error) => {
    const cid = clientDataMap.get(ws)?.username || wsId;
    console.error(`[SRV] WebSocket error for: ${cid}`, error);
    handleDisconnect(ws);
  });

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

    if (rateLimitBlockedUsers.has(ws) && Date.now() < rateLimitBlockedUsers.get(ws)!) {
      return;
    }
    if (!checkRateLimit(ws)) {
      return;
    }

    if (isPongMessage(parsedData)) {
      if (clientInfo) {
        clientInfo.isAlive = true;
      }
      return;
    }

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
      console.log(`[SRV] Validating credentials for: ${username} using Firestore`);

      const isValid = await validateCredentialsWithFirestore(username, password);

      if (isValid) {
        console.log(`[SRV] Credentials VALID for ${username} (Firestore).`);
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
        console.log(`[SRV] Login FAILED for: ${username} (Firestore).`);
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
      return;
    }

    if (!clientInfo) {
      console.log(`[SRV] Action rejected: Client ${clientIdForLog} is not logged in.`);
      sendToClient(ws, {
        type: ServerMessageType.SYSTEM,
        content: '[SRV]: Action requires login.',
      });
      return;
    }
    const currentUsername = clientInfo.username;

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

      const messageToSave: Omit<MessageHistoryDocument, 'timestamp'> = {
        sender: currentUsername,
        messageContent: ptm,
        isBroadcast: isB,
        ...(recipient && { recipient: recipient }),
      };
      await saveMessageToHistory(messageToSave);

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

    if (isStartTypingMessage(parsedData) || isStopTypingMessage(parsedData)) {
      const { recipient } = parsedData;
      const isB = !recipient;
      const mt = isStartTypingMessage(parsedData)
        ? ServerMessageType.USER_TYPING
        : ServerMessageType.USER_STOPPED_TYPING;
      const mts: UserTypingMessage | UserStoppedTypingMessage = {
        type: mt,
        sender: currentUsername,
        ...(recipient && { recipient: recipient }),
      };
      if (isB) {
        wss.clients.forEach((c) => {
          if (c !== ws && c.readyState === WebSocket.OPEN && clientDataMap.has(c)) {
            sendToClient(c, mts);
          }
        });
      } else if (recipient) {
        const rws = clientsByName.get(recipient);
        if (rws && rws.readyState === WebSocket.OPEN) {
          sendToClient(rws, mts);
        }
      }
      return;
    }

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

    console.warn(
      `[SRV] Unhandled message type: '${(parsedData as any).type}' from: ${currentUsername}`
    );
    sendToClient(ws, {
      type: ServerMessageType.SYSTEM,
      content: '[SRV]: Unrecognized message type.',
    });
  });

  ws.on('close', (code, reason) => {
    const rs = reason ? reason.toString('utf8') : 'N/A';
    const cun = clientDataMap.get(ws)?.username;
    console.log(`[SRV] Connection closed for: ${cun || wsId}, Code: ${code}, Reason: ${rs}`);
    handleDisconnect(ws);
  });

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
});

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

  server.close((err) => {
    if (err) {
      console.error('[SRV] Error closing HTTP server:', err);
      process.exit(1);
    } else {
      console.log('[SRV] HTTP Server closed gracefully.');
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

startServer().catch((err) => {
  console.error('[SRV] Failed to start server:', err);
  process.exit(1);
});