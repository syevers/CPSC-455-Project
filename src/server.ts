import bcrypt from 'bcrypt';
import { existsSync, readFileSync, writeFileSync } from 'fs';
import https from 'https';
import path from 'path';
import { fileURLToPath } from 'url';
import { WebSocket, WebSocketServer } from 'ws';

// Constants and Setup
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = 8080;
// Ensure certificate paths are correct relative to the execution directory
const options = {
  key: readFileSync(path.join(__dirname, '../certs/private.pem')),
  cert: readFileSync(path.join(__dirname, '../certs/public.pem')),
};
const ACCOUNTS_PATH = path.join(__dirname, 'accounts.json');
const RATE_LIMIT = 10; // Max messages per second
const BLOCK_DURATION = 10000; // 10 seconds block
const HEARTBEAT_INTERVAL = 30000; // 30 seconds ping interval
const SALT_ROUNDS = 10; // bcrypt complexity

// Interfaces
interface UserAccount {
  username: string;
  passwordHash: string;
}
interface AccountsData {
  users: UserAccount[];
}

// Message Types (Using const objects)
const ServerMessageType = {
  SYSTEM: 'system',
  USER_LIST: 'userList',
  CHAT: 'chat', // Legacy for unencrypted broadcast (can be removed later)
  PRIVATE_MESSAGE_ECHO: 'private_message_echo',
  RECEIVE_ENCRYPTED_MESSAGE: 'receive_encrypted_message', // For private messages
  RECEIVE_ENCRYPTED_BROADCAST_MESSAGE: 'receive_encrypted_broadcast_message', // For broadcast
  RECEIVE_PUBLIC_KEY: 'receive_public_key',
  PONG: 'pong',
  PING: 'ping',
} as const;

const ClientMessageType = {
  LOGIN: 'login',
  LOGOUT: 'logout',
  PRIVATE_MESSAGE: 'private_message',
  BROADCAST_MESSAGE: 'broadcast_message', // Legacy unencrypted broadcast (can be removed later)
  MULTI_RECIPIENT_ENCRYPTED_MESSAGE: 'multi_recipient_encrypted_message', // Encrypted broadcast from client
  SHARE_PUBLIC_KEY: 'share_public_key',
  REQUEST_PUBLIC_KEY: 'request_public_key',
  PING: 'ping',
  PONG: 'pong',
} as const;

type ServerMessageTypeValue = (typeof ServerMessageType)[keyof typeof ServerMessageType];
type ClientMessageTypeValue = (typeof ClientMessageType)[keyof typeof ClientMessageType];

// Message Interfaces
interface BaseMessage {
  type: ClientMessageTypeValue | ServerMessageTypeValue;
}
interface LoginMessage extends BaseMessage {
  type: typeof ClientMessageType.LOGIN;
  username: string;
  password?: string;
}
interface LogoutMessage extends BaseMessage {
  type: typeof ClientMessageType.LOGOUT;
  username?: string;
}
interface SharePublicKeyMessage extends BaseMessage {
  type: typeof ClientMessageType.SHARE_PUBLIC_KEY;
  publicKey: string;
}
interface RequestPublicKeyMessage extends BaseMessage {
  type: typeof ClientMessageType.REQUEST_PUBLIC_KEY;
  username: string;
}
interface EncryptedPayload {
  encryptedKey: string;
  iv: string;
  ciphertext: string;
}
interface EncryptedPrivateMessage extends BaseMessage {
  type: typeof ClientMessageType.PRIVATE_MESSAGE;
  recipient: string;
  payload: EncryptedPayload;
}
interface MultiRecipientEncryptedMessage extends BaseMessage {
  type: typeof ClientMessageType.MULTI_RECIPIENT_ENCRYPTED_MESSAGE;
  iv: string;
  ciphertext: string;
  encryptedKeys: { [recipientUsername: string]: string };
}
interface ReceiveEncryptedBroadcastMessage extends BaseMessage {
  type: typeof ServerMessageType.RECEIVE_ENCRYPTED_BROADCAST_MESSAGE;
  sender: string;
  iv: string;
  ciphertext: string;
  encryptedKey: string;
}
interface BroadcastMessage extends BaseMessage {
  type: typeof ClientMessageType.BROADCAST_MESSAGE;
  content: string;
}
interface PongMessage extends BaseMessage {
  type: typeof ClientMessageType.PONG;
}
// Interface for RECEIVE_PUBLIC_KEY message sent by server
interface ReceivePublicKeyServerMessage extends BaseMessage {
  type: typeof ServerMessageType.RECEIVE_PUBLIC_KEY;
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
}
function isRequestPublicKeyMessage(msg: any): msg is RequestPublicKeyMessage {
  return msg?.type === ClientMessageType.REQUEST_PUBLIC_KEY && typeof msg.username === 'string';
}
function isEncryptedPrivateMessage(msg: any): msg is EncryptedPrivateMessage {
  return (
    msg?.type === ClientMessageType.PRIVATE_MESSAGE &&
    typeof msg.recipient === 'string' &&
    typeof msg.payload?.encryptedKey === 'string' &&
    typeof msg.payload?.iv === 'string' &&
    typeof msg.payload?.ciphertext === 'string'
  );
}
function isMultiRecipientEncryptedMessage(msg: any): msg is MultiRecipientEncryptedMessage {
  return (
    msg?.type === ClientMessageType.MULTI_RECIPIENT_ENCRYPTED_MESSAGE &&
    typeof msg.iv === 'string' &&
    typeof msg.ciphertext === 'string' &&
    typeof msg.encryptedKeys === 'object' &&
    msg.encryptedKeys !== null &&
    Object.values(msg.encryptedKeys).every((key) => typeof key === 'string')
  );
}
function isBroadcastMessage(msg: any): msg is BroadcastMessage {
  return msg?.type === ClientMessageType.BROADCAST_MESSAGE && typeof msg.content === 'string';
}
function isPongMessage(msg: any): msg is PongMessage {
  return msg?.type === ClientMessageType.PONG;
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
    p.users = p.users.map((u: any) => ({
      username: u.username,
      passwordHash: u.passwordHash || '',
    }));
    return p as AccountsData;
  } catch (e) {
    console.error('[SRV] Error load/parse accounts.json:', e, '. Resetting.');
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
    console.log('[SRV] No password provided for new user:', username);
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
    console.error('[SRV] Invalid accounts data structure.');
    return false;
  }
  try {
    const userAccount = accounts.users.find(
      (usr) => usr.username.toLowerCase() === username.toLowerCase()
    );
    if (!userAccount) {
      console.log('[SRV] User not found, attempting to create:', username);
      if (!password) {
        console.log('[SRV] Cannot create user without password:', username);
        return false;
      }
      return addNewUser(username, password);
    } else {
      if (!password || !userAccount.passwordHash) {
        console.log(`[SRV] Login validation fail: Missing password/hash for ${username}`);
        return false;
      }
      const isValid = bcrypt.compareSync(password, userAccount.passwordHash);
      if (!isValid) {
        console.log(`[SRV] Login validation fail: Invalid password for ${username}`);
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
    if (!blockedUsers.has(ws)) {
      const id = ws.toString();
      console.log(`[SRV] Rate limit exceeded (${nt.length}/${RATE_LIMIT}mps). Blocking WS: ${id}`);
      blockedUsers.set(ws, n + BLOCK_DURATION);
      try {
        ws.send(
          JSON.stringify({
            type: ServerMessageType.SYSTEM,
            content: `[SRV]: Rate limit exceeded. Blocked ${BLOCK_DURATION / 1000}s.`,
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
  if (blockedUsers.has(ws) && n > blockedUsers.get(ws)!) {
    blockedUsers.delete(ws);
    console.log('[SRV] User unblocked. WS:', ws.toString());
  }
  return true;
}

// Broadcast/Send Functions
// Legacy unencrypted broadcast (can be removed if fully switching)
// function broadcastUnencrypted(senderWs: WebSocket, senderUsername: string, messageContent: string) {
//   const message = `[${senderUsername}]: ${messageContent}`;
//   console.log(`[SRV] Broadcasting (unencrypted): "${messageContent}" from ${senderUsername}`);
//   wss.clients.forEach((client) => {
//     if (client !== senderWs && client.readyState === WebSocket.OPEN && clientDataMap.has(client)) {
//       try {
//         client.send(JSON.stringify({ type: ServerMessageType.CHAT, content: message }));
//       } catch (se) {
//         console.error(`[SRV] Failed send broadcast to ${clientDataMap.get(client)?.username}:`, se);
//       }
//     }
//   });
// }

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
    wasLoggedIn = true;
    console.log(`[SRV] ${un} removed from active users.`);
  }
  clientDataMap.delete(ws);
  messageTimestamps.delete(ws);
  blockedUsers.delete(ws);
  console.log(`[SRV] Cleanup complete for WS: ${id}`);
  if (wasLoggedIn) {
    broadcastUserList();
  }
}
function startHeartbeat(ws: WebSocket) {
  stopHeartbeat(ws);
  const clientId = clientDataMap.get(ws)?.username || ws.toString();
  console.log(`[SRV] Starting heartbeat for ${clientId}`);
  const clientData = clientDataMap.get(ws);
  if (clientData) {
    clientData.isAlive = true;
  } else {
    console.error(`[SRV] Cannot start heartbeat for ${clientId}: client data not found.`);
    return;
  }
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
        console.log(`[SRV] Sending PING to ${currentClientId}`);
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
    console.log(`[SRV] Stopped heartbeat for ${clientDataMap.get(ws)?.username || ws.toString()}`);
  }
}

// WebSocket Server Initialization
const server = https.createServer(options).listen(PORT, '127.0.0.1', () => {
  console.log(`[SRV] Secure WebSocket Server running on wss://127.0.0.1:${PORT}`);
});
const wss = new WebSocketServer({ server });

// State Management
interface ClientData {
  username: string;
  publicKey?: string;
  isAlive?: boolean;
}
const clientDataMap = new Map<WebSocket, ClientData>();
const clientsByName = new Map<string, WebSocket>();
const publicKeys = new Map<string, string>(); // Stores Base64 encoded public keys
const heartbeatMap = new Map<WebSocket, NodeJS.Timeout>();
const messageTimestamps = new Map<WebSocket, number[]>();
const blockedUsers = new Map<WebSocket, number>();

console.log(`[SRV] Initializing... Loading accounts...`);
loadAccounts();
console.log(`[SRV] Initialization complete.`);

// Connection Handling
wss.on('connection', (ws, req) => {
  const remoteAddress = req.socket.remoteAddress || '?';
  const wsId = ws.toString();
  console.log(`[SRV] New client connected from ${remoteAddress}. WS ID: ${wsId}`);

  ws.on('error', (error) => {
    console.error('[SRV] WS error for:', clientDataMap.get(ws)?.username || wsId, error);
    handleDisconnect(ws);
  });

  ws.on('message', (data: Buffer) => {
    console.log(
      `[SRV] Raw data received from ${clientDataMap.get(ws)?.username || wsId}: ${data
        .toString()
        .substring(0, 150)}...`
    );
    let parsedData: BaseMessage;
    try {
      if (data.length > 10 * 1024) {
        console.warn(
          `[SRV] Large message (${data.length} bytes) from ${
            clientDataMap.get(ws)?.username || wsId
          }. Discarding.`
        );
        sendToClient(ws, { type: ServerMessageType.SYSTEM, content: 'Message too large.' });
        return;
      }
      parsedData = JSON.parse(data.toString());
      const logType = parsedData?.type || 'unknown';
      console.log(
        `[SRV] Received message type: '${logType}' from ${clientDataMap.get(ws)?.username || wsId}`
      );
    } catch (error) {
      console.error('[SRV] Failed parse JSON:', data.toString(), error);
      sendToClient(ws, { type: ServerMessageType.SYSTEM, content: 'Invalid JSON format.' });
      return;
    }

    if (blockedUsers.has(ws) && Date.now() < blockedUsers.get(ws)!) {
      return;
    }
    if (!checkRateLimit(ws)) {
      return;
    }

    const clientInfo = clientDataMap.get(ws);
    const currentUsername = clientInfo?.username;

    // Handle PONG
    if (isPongMessage(parsedData)) {
      if (clientInfo) {
        console.log(`[SRV] Received PONG from ${currentUsername || wsId}. Marking as alive.`);
        clientInfo.isAlive = true;
      } else {
        console.warn(`[SRV] Received PONG from unknown/disconnected client: ${wsId}`);
      }
      return;
    }

    // Handle Login
    if (isLoginMessage(parsedData)) {
      if (currentUsername) {
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
      console.log(`[SRV] Attempting login for username: ${username}`);
      if (clientsByName.has(username)) {
        console.log(`[SRV] Login failed: Username '${username}' already connected.`);
        sendToClient(ws, {
          type: ServerMessageType.SYSTEM,
          content: 'Login failed: User already connected.',
        });
        return;
      }
      console.log(`[SRV] Validating credentials for: ${username}`);
      if (validateCredentials(username, password)) {
        console.log(
          `[SRV] Credentials VALID for ${username}. Proceeding login setup. WS ID: ${wsId}`
        );
        const newClientData: ClientData = { username, isAlive: true };
        clientDataMap.set(ws, newClientData);
        clientsByName.set(username, ws);
        console.log(`[SRV] Client data set for ${username}.`);
        try {
          sendToClient(ws, { type: ServerMessageType.SYSTEM, content: 'Login successful!' });
          console.log(`[SRV] Login success message sent to ${username}.`);
        } catch (e) {
          console.error(`[SRV] Error sending login success to ${username}:`, e);
          handleDisconnect(ws);
          return;
        }
        try {
          broadcastUserList();
          console.log(`[SRV] User list broadcast complete for ${username}'s login.`);
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
        console.log(`[SRV] Login failed for: ${username} (Invalid credentials or create failed).`);
        sendToClient(ws, {
          type: ServerMessageType.SYSTEM,
          content: 'Login failed: Invalid username or password.',
        });
      }
      return;
    }

    // Actions Requiring Login
    if (!currentUsername || !clientInfo) {
      sendToClient(ws, {
        type: ServerMessageType.SYSTEM,
        content: '[SRV]: Action requires login.',
      });
      return;
    }

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
      const sharedKey = parsedData.publicKey;
      console.log(`[SRV] Received public key from ${currentUsername}`);
      if (sharedKey && typeof sharedKey === 'string' && sharedKey.length > 100) {
        // Basic validation
        clientInfo.publicKey = sharedKey;
        publicKeys.set(currentUsername, sharedKey);
        console.log(`[SRV] Public key stored for ${currentUsername}.`);

        console.log(`[SRV] Broadcasting ${currentUsername}'s public key to other users...`);
        const messageToSend: ReceivePublicKeyServerMessage = {
          type: ServerMessageType.RECEIVE_PUBLIC_KEY,
          username: currentUsername,
          publicKey: sharedKey,
        };
        wss.clients.forEach((otherClient) => {
          // Send to other OPEN, LOGGED-IN clients
          if (
            otherClient !== ws &&
            otherClient.readyState === WebSocket.OPEN &&
            clientDataMap.has(otherClient)
          ) {
            const targetUsername = clientDataMap.get(otherClient)?.username;
            console.log(`   -> Sending key to ${targetUsername}`);
            sendToClient(otherClient, messageToSend);
          }
        });
        console.log(`[SRV] Finished broadcasting ${currentUsername}'s public key.`);
      } else {
        console.warn(`[SRV] Invalid public key format received from ${currentUsername}.`);
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
      const targetKey = publicKeys.get(targetUsername);
      if (targetKey) {
        // Key found, send it back to the requester
        const messageToSend: ReceivePublicKeyServerMessage = {
          type: ServerMessageType.RECEIVE_PUBLIC_KEY,
          username: targetUsername,
          publicKey: targetKey,
        };
        sendToClient(ws, messageToSend);
      } else {
        // Key not found (user might be offline or hasn't shared key yet)
        // Server already handles this by broadcasting keys on share, so this response might be less critical
        // but we keep it for cases where the key genuinely isn't available.
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

    // Handle Encrypted Private Message
    if (isEncryptedPrivateMessage(parsedData)) {
      const { recipient, payload } = parsedData;
      const recipientWs = clientsByName.get(recipient);
      console.log(
        `[SRV] Relaying encrypted PRIVATE message from ${currentUsername} to ${recipient}`
      );
      if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
        const messageToSend = {
          type: ServerMessageType.RECEIVE_ENCRYPTED_MESSAGE,
          sender: currentUsername,
          payload: payload,
        };
        sendToClient(recipientWs, messageToSend);
        sendToClient(ws, {
          type: ServerMessageType.PRIVATE_MESSAGE_ECHO,
          recipient: recipient,
          payload: payload,
        });
      } else {
        console.log(`[SRV] Private message relay failed: Recipient '${recipient}' offline.`);
        sendToClient(ws, {
          type: ServerMessageType.SYSTEM,
          content: `[SRV]: User '${recipient}' is offline.`,
        });
      }
      return;
    }

    // Handle Encrypted Broadcast Message from Client
    if (isMultiRecipientEncryptedMessage(parsedData)) {
      const { iv, ciphertext, encryptedKeys } = parsedData;
      console.log(
        `[SRV] Received encrypted BROADCAST from ${currentUsername} for ${
          Object.keys(encryptedKeys).length
        } recipients.`
      );
      let recipientsFound = 0;
      for (const recipientUsername in encryptedKeys) {
        if (Object.prototype.hasOwnProperty.call(encryptedKeys, recipientUsername)) {
          const recipientWs = clientsByName.get(recipientUsername);
          const encryptedKeyForRecipient = encryptedKeys[recipientUsername];
          if (
            recipientWs &&
            recipientWs.readyState === WebSocket.OPEN &&
            encryptedKeyForRecipient
          ) {
            const messageToSend: ReceiveEncryptedBroadcastMessage = {
              type: ServerMessageType.RECEIVE_ENCRYPTED_BROADCAST_MESSAGE,
              sender: currentUsername,
              iv: iv,
              ciphertext: ciphertext,
              encryptedKey: encryptedKeyForRecipient,
            };
            sendToClient(recipientWs, messageToSend);
            recipientsFound++;
          } else {
            console.log(
              `[SRV] Broadcast relay skipped for offline/missing user: ${recipientUsername}`
            );
          }
        }
      }
      console.log(`[SRV] Relayed encrypted broadcast to ${recipientsFound} online recipients.`);
      return;
    }

    // Legacy Unencrypted Broadcast
    // if (isBroadcastMessage(parsedData)) {
    //   const { content } = parsedData;
    //   if (
    //     !content ||
    //     typeof content !== 'string' ||
    //     content.length === 0 ||
    //     content.length > 1024
    //   ) {
    //     sendToClient(ws, {
    //       type: ServerMessageType.SYSTEM,
    //       content: '[SRV]: Invalid broadcast content/length.',
    //     });
    //     return;
    //   }
    //   console.warn(
    //     `[SRV] Received LEGACY unencrypted broadcast from ${currentUsername}. Relaying...`
    //   );
    //   broadcastUnencrypted(ws, currentUsername, content);
    //   return;
    // }

    // Unhandled Message Type
    console.warn(
      '[SRV] Unhandled message type:',
      (parsedData as any).type,
      'from:',
      currentUsername
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
        content: 'Welcome to SecureChat! Please log in.',
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
// (shutdown function - No changes needed)
const shutdown = () => {
  console.log('[SRV] Shutting down server...');
  wss.clients.forEach((client) => {
    stopHeartbeat(client);
    if (client.readyState === WebSocket.OPEN) {
      client.close(1012, 'Server shutting down');
    }
  });
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
