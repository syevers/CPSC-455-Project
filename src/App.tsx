import React, { useCallback, useEffect, useRef, useState } from 'react';
// Import UI components & libraries
import DOMPurify from 'dompurify';
import EmojiPicker, { EmojiClickData, Theme as EmojiTheme } from 'emoji-picker-react';
import { marked } from 'marked';
import TextareaAutosize from 'react-textarea-autosize';

// Shadcn UI Component Imports
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Progress } from '@/components/ui/progress';
import { ScrollArea } from '@/components/ui/scroll-area';

// Icons
import {
  AlertCircle,
  Check,
  Circle,
  Download,
  File as FileIcon,
  Lock,
  LogOut,
  MessageSquare,
  Paperclip,
  SendHorizonal,
  Smile,
  Trash2,
  Unlock,
  Upload,
  User,
  Users,
  X,
} from 'lucide-react';

// Constants
const MAX_FILE_SIZE = 10 * 1024 * 1024;
const CHUNK_SIZE = 64 * 1024;
const SERVER_URL = 'wss://127.0.0.1:8080';
const ALL_CHAT_KEY = 'All Chat';
const TYPING_TIMEOUT_MS = 2000; // Stop typing after 2 seconds of inactivity
const TYPING_THROTTLE_MS = 5000; // Send START_TYPING max once every 5 seconds

// Crypto Helper Functions
const bufferToBase64 = (buffer: ArrayBuffer): string => {
  let b = '';
  const B = new Uint8Array(buffer);
  const l = B.byteLength;
  for (let i = 0; i < l; i++) {
    b += String.fromCharCode(B[i]);
  }
  return btoa(b);
};
const base64ToBuffer = (base64: string): ArrayBuffer => {
  const bs = atob(base64);
  const l = bs.length;
  const B = new Uint8Array(l);
  for (let i = 0; i < l; i++) {
    B[i] = bs.charCodeAt(i);
  }
  return B.buffer;
};
const generateRsaKeyPair = async (): Promise<CryptoKeyPair> => {
  console.log('Generating Client RSA-OAEP 4096 key pair...');
  const kp = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt']
  );
  console.log('Client RSA key pair generated.');
  return kp;
};
const exportPublicKey = async (key: CryptoKey): Promise<string> => {
  const es = await crypto.subtle.exportKey('spki', key);
  return bufferToBase64(es);
};
const importPublicKeyPem = async (pem: string): Promise<CryptoKey> => {
  const h = '-----BEGIN PUBLIC KEY-----';
  const f = '-----END PUBLIC KEY-----';
  const c = pem.substring(h.length, pem.length - f.length - 1).replace(/\s+/g, '');
  const bd = base64ToBuffer(c);
  return await crypto.subtle.importKey('spki', bd, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, [
    'encrypt',
  ]);
};
const importUserPublicKey = async (base64Key: string): Promise<CryptoKey> => {
  const sb = base64ToBuffer(base64Key);
  return await crypto.subtle.importKey('spki', sb, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, [
    'encrypt',
  ]);
};
const generateAesKey = async (): Promise<CryptoKey> => {
  return await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ]);
};
const exportAesKeyRaw = async (key: CryptoKey): Promise<string> => {
  const er = await crypto.subtle.exportKey('raw', key);
  return bufferToBase64(er);
};
const importAesKeyRaw = async (base64Key: string): Promise<CryptoKey> => {
  const rb = base64ToBuffer(base64Key);
  return await crypto.subtle.importKey('raw', rb, { name: 'AES-GCM' }, true, [
    'encrypt',
    'decrypt',
  ]);
};
const encryptAesGcm = async (
  key: CryptoKey,
  data: ArrayBuffer
): Promise<{ iv: string; ciphertext: string }> => {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cb = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, data);
  return { iv: bufferToBase64(iv), ciphertext: bufferToBase64(cb) };
};
const decryptAesGcm = async (
  key: CryptoKey,
  ivBase64: string,
  ciphertextBase64: string
): Promise<ArrayBuffer> => {
  const iv = base64ToBuffer(ivBase64);
  const ct = base64ToBuffer(ciphertextBase64);
  try {
    const db = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ct);
    return db;
  } catch (e) {
    console.error('AES-GCM Decryption failed:', e);
    throw new Error('AES Decryption Failed');
  }
};
const encryptRsaOaep = async (publicKey: CryptoKey, data: ArrayBuffer): Promise<string> => {
  const eb = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, data);
  return bufferToBase64(eb);
};
const decryptRsaOaep = async (privateKey: CryptoKey, base64Data: string): Promise<ArrayBuffer> => {
  const eb = base64ToBuffer(base64Data);
  try {
    return await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, eb);
  } catch (e) {
    console.error('RSA-OAEP Decryption failed:', e);
    throw new Error('RSA Decryption Failed');
  }
};

// Message Types
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

// Client-Side Interfaces
interface ServerMessageBase {
  type: ServerMessageType;
}
interface SystemMessage extends ServerMessageBase {
  type: ServerMessageType.SYSTEM;
  content: string;
}
interface UserListMessage extends ServerMessageBase {
  type: ServerMessageType.USER_LIST;
  users: string[];
}
interface ReceivePublicKeyMessage extends ServerMessageBase {
  type: ServerMessageType.RECEIVE_PUBLIC_KEY;
  username: string;
  publicKey: string;
}
interface PingMessage extends ServerMessageBase {
  type: ServerMessageType.PING;
}
interface ServerPublicKeyMessage extends ServerMessageBase {
  type: ServerMessageType.SERVER_PUBLIC_KEY;
  publicKey: string;
}
interface ServerReceiveMessage extends ServerMessageBase {
  type: ServerMessageType.RECEIVE_MESSAGE;
  sender: string;
  isBroadcast: boolean;
  payload: { iv: string; encryptedKey: string; ciphertext: string };
}
// File Transfer Interfaces
interface FileInfo {
  name: string;
  size: number;
  type: string;
  iv: string;
  encryptedKey: string;
}
interface IncomingFileRequestMessage extends ServerMessageBase {
  type: ServerMessageType.INCOMING_FILE_REQUEST;
  sender: string;
  fileInfo: FileInfo;
}
interface FileAcceptNoticeMessage extends ServerMessageBase {
  type: ServerMessageType.FILE_ACCEPT_NOTICE;
  recipient: string;
  fileInfo: { name: string; size: number };
}
interface FileRejectNoticeMessage extends ServerMessageBase {
  type: ServerMessageType.FILE_REJECT_NOTICE;
  recipient: string;
  fileInfo: { name: string };
}
interface FileChunkReceiveMessage extends ServerMessageBase {
  type: ServerMessageType.FILE_CHUNK_RECEIVE;
  sender: string;
  fileInfo: { name: string };
  chunkData: string;
  chunkIndex: number;
  isLastChunk: boolean;
}
// History Interfaces
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
interface ReceiveHistoryMessage extends ServerMessageBase {
  type: ServerMessageType.RECEIVE_HISTORY;
  history: PersistedChatHistories;
}
// Typing Indicator Interfaces
interface UserTypingMessage extends ServerMessageBase {
  type: ServerMessageType.USER_TYPING;
  sender: string;
  recipient?: string;
}
interface UserStoppedTypingMessage extends ServerMessageBase {
  type: ServerMessageType.USER_STOPPED_TYPING;
  sender: string;
  recipient?: string;
}

// Combined type for all possible server messages
type ServerMessage =
  | SystemMessage
  | UserListMessage
  | ReceivePublicKeyMessage
  | ServerPublicKeyMessage
  | ServerReceiveMessage
  | PingMessage
  | IncomingFileRequestMessage
  | FileAcceptNoticeMessage
  | FileRejectNoticeMessage
  | FileChunkReceiveMessage
  | ReceiveHistoryMessage
  | UserTypingMessage
  | UserStoppedTypingMessage;

// UI State Interfaces
interface DisplayMessage {
  type: 'system' | 'chat' | 'my_chat' | 'error' | 'file_request' | 'file_notice' | 'file_image';
  content: string | React.ReactNode;
  sender?: string;
  recipient?: string;
  timestamp?: number;
  isEncrypted?: boolean;
  fileInfo?: FileInfo | { name: string; size?: number; type?: string };
  transferId?: string;
  objectUrl?: string;
}
interface ChatHistories {
  [peerUsernameOrAllChat: string]: DisplayMessage[];
}
// Typing state: Maps chat context (peerKey) to a Set of usernames typing in that context
interface TypingUsersState {
  [peerKey: string]: Set<string>;
}

// File Transfer State Interfaces
interface FileTransferRequest {
  id: string;
  sender: string;
  fileInfo: FileInfo;
  timestamp: number;
}
interface SendingFileState {
  file: File;
  encryptedContent: ArrayBuffer | null;
  recipient: string;
  fileInfo: FileInfo;
  totalChunks: number;
  nextChunkIndex: number;
  status: 'pending_accept' | 'sending' | 'complete' | 'rejected' | 'error';
}
interface ReceivingFileState {
  id: string;
  sender: string;
  fileInfo: FileInfo;
  aesKey: CryptoKey | null;
  chunks: ArrayBuffer[];
  receivedBytes: number;
  status: 'receiving' | 'complete' | 'error' | 'decrypting';
}

// Helper to generate unique IDs
const generateUniqueId = () =>
  `transfer_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;

// React Component
function App(): React.ReactElement {
  // State & Refs
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const [isLoggedIn, setIsLoggedIn] = useState<boolean>(false);
  const [username, setUsername] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [currentUsername, setCurrentUsername] = useState<string>('');
  const [chatHistories, setChatHistories] = useState<ChatHistories>({ [ALL_CHAT_KEY]: [] });
  const [users, setUsers] = useState<string[]>([]); // Still needed for online status
  const [inputValue, setInputValue] = useState<string>('');
  const [loginError, setLoginError] = useState<string>('');
  const [systemMessage, setSystemMessage] = useState<string>('');
  const [selectedUser, setSelectedUser] = useState<string | null>(null);
  const ws = useRef<WebSocket | null>(null);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);
  const isConnecting = useRef<boolean>(false);
  const usernameRef = useRef<string>('');
  const isMounted = useRef<boolean>(true);
  const reconnectTimeoutId = useRef<NodeJS.Timeout | null>(null);
  const connectTimeoutId = useRef<NodeJS.Timeout | null>(null);
  const hasSharedKey = useRef<boolean>(false);
  const keyPairRef = useRef<CryptoKeyPair | null>(null);
  const [myKeyPairState, setMyKeyPairState] = useState<CryptoKeyPair | null>(null);
  const [peerPublicKeys, setPeerPublicKeys] = useState<Map<string, CryptoKey>>(new Map());
  const [serverPublicKey, setServerPublicKey] = useState<CryptoKey | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [incomingFileRequests, setIncomingFileRequests] = useState<
    Map<string, FileTransferRequest>
  >(new Map());
  const sendingFiles = useRef<Map<string, SendingFileState>>(new Map());
  const receivingFiles = useRef<Map<string, ReceivingFileState>>(new Map());
  const [transferProgress, setTransferProgress] = useState<{ [transferId: string]: number }>({});
  const [showEmojiPicker, setShowEmojiPicker] = useState<boolean>(false);
  const messageInputRef = useRef<HTMLTextAreaElement>(null);
  const [isHistoryLoading, setIsHistoryLoading] = useState<boolean>(false);
  // Typing indicator state
  const [typingUsers, setTypingUsers] = useState<TypingUsersState>({});
  const typingTimeoutRef = useRef<NodeJS.Timeout | null>(null); // Timeout for STOP_TYPING
  const typingSentTimestampRef = useRef<number>(0); // Throttle START_TYPING

  // Effects
  const currentChatKey = selectedUser ?? ALL_CHAT_KEY;
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [chatHistories, currentChatKey]);
  const addMessageToHistory = useCallback(
    (peerKey: string, message: Omit<DisplayMessage, 'timestamp'>) => {
      if (!isMounted.current) return;
      const newMessage = { ...message, timestamp: Date.now() };
      setChatHistories((prev) => {
        const history = prev[peerKey] || [];
        if (
          newMessage.transferId &&
          (newMessage.type === 'file_notice' || newMessage.type === 'file_request') &&
          history.some((m) => m.transferId === newMessage.transferId && m.type === newMessage.type)
        ) {
          return prev;
        }
        return { ...prev, [peerKey]: [...history, newMessage] };
      });
    },
    []
  );
  useEffect(() => {
    isMounted.current = true;
    const setupCrypto = async () => {
      try {
        const keys = await generateRsaKeyPair();
        if (isMounted.current) {
          setMyKeyPairState(keys);
          keyPairRef.current = keys;
          console.log('Client RSA key pair generated.');
        }
      } catch (e) {
        console.error('Client RSA key generation failed:', e);
        if (isMounted.current) setLoginError('CRITICAL: Cannot generate keys.');
      }
    };
    setupCrypto();
    return () => {
      isMounted.current = false;
    };
  }, []);

  // WebSocket Connection and Message Handling Effect
  useEffect(() => {
    let isEffectMounted = true;
    let localWsInstance: WebSocket | null = null;
    const connect = () => {
      if (isConnecting.current || (ws.current && ws.current.readyState === WebSocket.OPEN)) return;
      if (reconnectTimeoutId.current) {
        clearTimeout(reconnectTimeoutId.current);
        reconnectTimeoutId.current = null;
      }
      console.log('[WS] Attempting connection...');
      isConnecting.current = true;
      if (isEffectMounted) {
        setSystemMessage('Connecting...');
        setLoginError('');
      } else {
        console.log('[WS] Connect aborted: effect unmounted.');
        isConnecting.current = false;
        return;
      }
      if (ws.current) {
        console.warn('[WS] ws.current not null before new connection.');
        ws.current.onopen = null;
        ws.current.onclose = null;
        ws.current.onerror = null;
        ws.current.onmessage = null;
        if (
          ws.current.readyState === WebSocket.OPEN ||
          ws.current.readyState === WebSocket.CONNECTING
        )
          ws.current.close();
        ws.current = null;
      }
      const currentRunWs = new WebSocket(SERVER_URL);
      localWsInstance = currentRunWs;
      ws.current = currentRunWs;
      console.log('[WS] New WebSocket instance created.');
      currentRunWs.onopen = () => {
        if (ws.current !== currentRunWs || !isEffectMounted) return;
        console.log('[WS] WebSocket Connected (onopen)');
        isConnecting.current = false;
        setIsConnected(true);
        setSystemMessage('');
        setLoginError('');
      };
      currentRunWs.onclose = (event: CloseEvent) => {
        if (localWsInstance !== currentRunWs) return;
        console.log(
          `[WS] WebSocket Disconnected (onclose). Code: ${event.code}, Reason: ${event.reason}`
        );
        isConnecting.current = false;
        if (ws.current === currentRunWs) {
          ws.current = null;
        }
        localWsInstance = null;
        if (isEffectMounted) {
          setIsConnected(false);
          setIsLoggedIn(false);
          setCurrentUsername('');
          usernameRef.current = '';
          setUsers([]);
          setPeerPublicKeys(new Map());
          setServerPublicKey(null);
          setSelectedUser(null);
          setChatHistories({ [ALL_CHAT_KEY]: [] });
          setTypingUsers({});
          setSystemMessage('Disconnected. Reconnecting...');
          hasSharedKey.current = false;
          if (reconnectTimeoutId.current) clearTimeout(reconnectTimeoutId.current);
          console.log('[WS] Scheduling reconnection attempt in 5s...');
          reconnectTimeoutId.current = setTimeout(() => {
            if (isEffectMounted && !ws.current && !isConnecting.current) connect();
          }, 5000);
        }
      };
      currentRunWs.onerror = (event: Event) => {
        if (localWsInstance !== currentRunWs || !isEffectMounted) return;
        console.error('[WS] WebSocket Error:', event);
        isConnecting.current = false;
      };

      // onmessage Handler
      currentRunWs.onmessage = async (event: MessageEvent) => {
        if (ws.current !== currentRunWs || !isEffectMounted) return;
        try {
          const message = JSON.parse(event.data as string) as ServerMessage;
          switch (message.type) {
            case ServerMessageType.SYSTEM: {
              const content = message.content ?? '';
              if (content === 'Login successful!') {
                const loggedInUsername = usernameRef.current;
                if (!loggedInUsername) {
                  console.error('CRITICAL: usernameRef is empty!');
                  setLoginError('Login failed: Internal error.');
                  setIsLoggedIn(false);
                  setCurrentUsername('');
                  break;
                }
                setCurrentUsername(loggedInUsername);
                setIsLoggedIn(true);
                setLoginError('');
                setSystemMessage('');
                setUsername('');
                setPassword('');
                addMessageToHistory(ALL_CHAT_KEY, {
                  type: 'system',
                  content: `[SERVER]: ${content}`,
                });
                hasSharedKey.current = false;
                console.log('[WS] Login successful, requesting history...');
                setIsHistoryLoading(true);
                sendData({ type: ClientMessageType.REQUEST_HISTORY });
              } else if (content.startsWith('Login failed')) {
                setLoginError(content);
                setSystemMessage('');
                setIsLoggedIn(false);
                setCurrentUsername('');
                usernameRef.current = '';
              } else {
                if (!content.startsWith('Public key for user'))
                  addMessageToHistory(ALL_CHAT_KEY, {
                    type: 'system',
                    content: `[SERVER]: ${content}`,
                  });
              }
              break;
            }
            case ServerMessageType.RECEIVE_HISTORY: {
              console.log('[WS] Received history from server.');
              setIsHistoryLoading(false);
              if (message.history && typeof message.history === 'object') {
                setChatHistories(message.history as ChatHistories);
                console.log('[WS] History applied to state.');
              } else {
                console.error('[WS] Invalid history data received:', message.history);
                addMessageToHistory(ALL_CHAT_KEY, {
                  type: 'error',
                  content: '[Error] Failed to load chat history.',
                });
              }
              break;
            }
            case ServerMessageType.USER_TYPING: {
              const { sender, recipient } = message;
              const peerKey = recipient
                ? sender === currentUsername
                  ? recipient
                  : sender
                : ALL_CHAT_KEY;
              setTypingUsers((prev) => {
                const uc = new Set(prev[peerKey] || []);
                uc.add(sender);
                return { ...prev, [peerKey]: uc };
              });
              break;
            }
            case ServerMessageType.USER_STOPPED_TYPING: {
              const { sender, recipient } = message;
              const peerKey = recipient
                ? sender === currentUsername
                  ? recipient
                  : sender
                : ALL_CHAT_KEY;
              setTypingUsers((prev) => {
                const uc = new Set(prev[peerKey] || []);
                uc.delete(sender);
                if (uc.size === 0) {
                  const ns = { ...prev };
                  delete ns[peerKey];
                  return ns;
                }
                return { ...prev, [peerKey]: uc };
              });
              break;
            }
            case ServerMessageType.USER_LIST: {
              const nu = message.users ?? [];
              const lu = usernameRef.current;
              // Update the online users list state
              setUsers(nu);
              // Check if the currently selected user went offline
              if (selectedUser && !nu.includes(selectedUser)) {
                addMessageToHistory(selectedUser, {
                  type: 'system',
                  content: `User ${selectedUser} went offline.`,
                });
                // Don't deselect the user, just update their status indicator in the sidebar
                // setSelectedUser(null); // Keep the conversation selected
              }
              // Update peer public keys (request missing keys for newly online users)
              setPeerPublicKeys((pk) => {
                const uk = new Map(pk);
                let c = false;
                // Remove keys for users who are no longer online (optional, could keep keys)
                // Array.from(uk.keys()).forEach((u) => { if (!nu.includes(u)) { uk.delete(u); c = true; } });
                if (lu) {
                  nu.forEach((u) => {
                    if (u !== lu && !uk.has(u)) {
                      // Request key only if not already present
                      console.log(`[WS] Requesting public key for newly online user: ${u}`);
                      sendData({ type: ClientMessageType.REQUEST_PUBLIC_KEY, username: u });
                    }
                  });
                }
                return c ? uk : pk; // Return existing map if no keys were removed
              });
              break;
            }
            case ServerMessageType.SERVER_PUBLIC_KEY: {
              try {
                const ik = await importPublicKeyPem(message.publicKey);
                setServerPublicKey(ik);
              } catch (e) {
                console.error('[ERROR] Failed to import server public key:', e);
                setLoginError('Error processing server key.');
                if (ws.current) ws.current.close();
              }
              break;
            }
            case ServerMessageType.RECEIVE_PUBLIC_KEY: {
              try {
                const ik = await importUserPublicKey(message.publicKey);
                setPeerPublicKeys((p) => new Map(p).set(message.username, ik));
                if (selectedUser === message.username)
                  addMessageToHistory(selectedUser, {
                    type: 'system',
                    content: `Encryption key received for ${selectedUser}.`,
                  });
              } catch (ie) {
                console.error(`Failed to import public key for ${message.username}:`, ie);
                addMessageToHistory(message.username, {
                  type: 'error',
                  content: `Invalid key from ${message.username}.`,
                });
              }
              break;
            }
            case ServerMessageType.RECEIVE_MESSAGE: {
              const { sender, isBroadcast, payload } = message;
              const { iv, encryptedKey, ciphertext } = payload;
              const mpk = keyPairRef.current?.privateKey;
              if (!mpk) {
                addMessageToHistory(isBroadcast ? ALL_CHAT_KEY : sender, {
                  type: 'error',
                  content: '[Error] Cannot decrypt: Missing private key.',
                });
                break;
              }
              try {
                const akb = await decryptRsaOaep(mpk, encryptedKey);
                const ak = await importAesKeyRaw(bufferToBase64(akb));
                const dc = await decryptAesGcm(ak, iv, ciphertext);
                const dt = new TextDecoder().decode(dc);
                addMessageToHistory(isBroadcast ? ALL_CHAT_KEY : sender, {
                  type: 'chat',
                  content: dt,
                  sender: sender,
                  isEncrypted: true,
                });
              } catch (de) {
                console.error(`Failed to decrypt message from ${sender}:`, de);
                addMessageToHistory(isBroadcast ? ALL_CHAT_KEY : sender, {
                  type: 'error',
                  content: `[Decryption Failed from ${sender}]`,
                  sender: sender,
                });
              }
              break;
            }
            case ServerMessageType.PING: {
              try {
                sendData({ type: ClientMessageType.PONG });
              } catch (e) {
                console.error('[ERROR] Failed to send PONG:', e);
              }
              break;
            }
            case ServerMessageType.INCOMING_FILE_REQUEST: {
              const { sender, fileInfo } = message;
              const tid = generateUniqueId();
              const req: FileTransferRequest = { id: tid, sender, fileInfo, timestamp: Date.now() };
              setIncomingFileRequests((p) => new Map(p).set(tid, req));
              addMessageToHistory(sender, {
                type: 'file_request',
                sender,
                content: `Wants to send you a file:`,
                fileInfo,
                transferId: tid,
              });
              break;
            }
            case ServerMessageType.FILE_ACCEPT_NOTICE: {
              const { recipient, fileInfo } = message;
              let tid: string | null = null;
              sendingFiles.current.forEach((s, id) => {
                if (
                  s.recipient === recipient &&
                  s.fileInfo.name === fileInfo.name &&
                  s.status === 'pending_accept'
                )
                  tid = id;
              });
              if (tid && sendingFiles.current.has(tid)) {
                const ss = sendingFiles.current.get(tid)!;
                if (ss.encryptedContent) {
                  ss.status = 'sending';
                  addMessageToHistory(recipient, {
                    type: 'file_notice',
                    content: `User accepted file: ${fileInfo.name}. Sending...`,
                    transferId: tid,
                  });
                  sendChunk(tid, ss);
                } else {
                  sendingFiles.current.delete(tid);
                  addMessageToHistory(recipient, {
                    type: 'error',
                    content: `Error starting transfer: Missing content.`,
                    transferId: tid,
                  });
                }
              }
              break;
            }
            case ServerMessageType.FILE_REJECT_NOTICE: {
              const { recipient, fileInfo } = message;
              let tid: string | null = null;
              sendingFiles.current.forEach((s, id) => {
                if (
                  s.recipient === recipient &&
                  s.fileInfo.name === fileInfo.name &&
                  s.status === 'pending_accept'
                )
                  tid = id;
              });
              if (tid) {
                sendingFiles.current.delete(tid);
                addMessageToHistory(recipient, {
                  type: 'file_notice',
                  content: `User rejected file: ${fileInfo.name}`,
                  transferId: tid,
                });
                setTransferProgress((p) => {
                  const n = { ...p };
                  delete n[tid!];
                  return n;
                });
              }
              break;
            }
            case ServerMessageType.FILE_CHUNK_RECEIVE: {
              const { sender, fileInfo, chunkData, chunkIndex, isLastChunk } = message;
              let tid: string | null = null;
              receivingFiles.current.forEach((s, id) => {
                if (
                  s.sender === sender &&
                  s.fileInfo.name === fileInfo.name &&
                  s.status === 'receiving'
                )
                  tid = id;
              });
              if (!tid || !receivingFiles.current.has(tid)) break;
              const rs = receivingFiles.current.get(tid)!;
              if (!rs.aesKey) {
                receivingFiles.current.delete(tid);
                addMessageToHistory(sender, {
                  type: 'error',
                  content: `Transfer error: Missing key.`,
                  transferId: tid,
                });
                break;
              }
              try {
                const cb = base64ToBuffer(chunkData);
                rs.chunks.push(cb);
                rs.receivedBytes += cb.byteLength;
                const pr = Math.round((rs.receivedBytes / rs.fileInfo.size) * 100);
                setTransferProgress((p) => ({ ...p, [tid!]: pr }));
                if (isLastChunk) {
                  rs.status = 'decrypting';
                  addMessageToHistory(sender, {
                    type: 'file_notice',
                    content: `File received: ${fileInfo.name}. Decrypting...`,
                    transferId: tid,
                  });
                  const teb = new Uint8Array(rs.receivedBytes);
                  let o = 0;
                  for (const c of rs.chunks) {
                    teb.set(new Uint8Array(c), o);
                    o += c.byteLength;
                  }
                  const dfb = await decryptAesGcm(
                    rs.aesKey,
                    rs.fileInfo.iv,
                    bufferToBase64(teb.buffer)
                  );
                  rs.status = 'complete';
                  const ft = rs.fileInfo.type || 'application/octet-stream';
                  const blob = new Blob([dfb], { type: ft });
                  const ou = URL.createObjectURL(blob);
                  if (ft.startsWith('image/')) {
                    addMessageToHistory(sender, {
                      type: 'file_image',
                      sender,
                      content: `Received image: ${fileInfo.name}`,
                      fileInfo: rs.fileInfo,
                      transferId: tid,
                      objectUrl: ou,
                    });
                  } else {
                    const a = document.createElement('a');
                    a.href = ou;
                    a.download = rs.fileInfo.name;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(ou);
                    addMessageToHistory(sender, {
                      type: 'file_notice',
                      content: `File downloaded: ${fileInfo.name}`,
                      transferId: tid,
                    });
                  }
                  receivingFiles.current.delete(tid);
                  setTransferProgress((p) => {
                    const n = { ...p };
                    delete n[tid!];
                    return n;
                  });
                }
              } catch (e) {
                receivingFiles.current.delete(tid);
                addMessageToHistory(sender, {
                  type: 'error',
                  content: `Transfer failed: ${e instanceof Error ? e.message : 'Unknown'}`,
                  transferId: tid,
                });
                setTransferProgress((p) => {
                  const n = { ...p };
                  delete n[tid!];
                  return n;
                });
              }
              break;
            }
            default:
              console.warn('[WS] Unhandled server message type:', (message as any).type);
          }
        } catch (error) {
          console.error('[WS] Error processing message:', error, 'Raw:', event.data);
          addMessageToHistory(ALL_CHAT_KEY, {
            type: 'error',
            content: `[Client Error]: Failed processing message.`,
          });
        }
      }; // End onmessage
    }; // End connect
    if (connectTimeoutId.current) clearTimeout(connectTimeoutId.current);
    connectTimeoutId.current = setTimeout(() => {
      if (isEffectMounted) connect();
    }, 10);
    return () => {
      isEffectMounted = false;
      console.log('[WS] Connection useEffect cleanup.');
      Object.values(chatHistories)
        .flat()
        .forEach((m) => {
          if (m.objectUrl) URL.revokeObjectURL(m.objectUrl);
        });
      if (connectTimeoutId.current) clearTimeout(connectTimeoutId.current);
      if (reconnectTimeoutId.current) clearTimeout(reconnectTimeoutId.current);
      const stc = localWsInstance;
      localWsInstance = null;
      if (ws.current === stc) ws.current = null;
      if (stc) {
        stc.onopen = null;
        stc.onclose = null;
        stc.onerror = null;
        stc.onmessage = null;
        if (stc.readyState === WebSocket.OPEN || stc.readyState === WebSocket.CONNECTING) {
          try {
            stc.close(1000, 'Component unmounted');
          } catch (e) {}
        }
      }
    };
  }, [addMessageToHistory]); // Keep dependency array minimal

  // Effect for Sharing User's Public Key
  useEffect(() => {
    if (isLoggedIn && isConnected && myKeyPairState?.publicKey && !hasSharedKey.current) {
      const shareKey = async () => {
        if (!keyPairRef.current?.publicKey) return;
        try {
          const epk = await exportPublicKey(keyPairRef.current.publicKey);
          sendData({ type: ClientMessageType.SHARE_PUBLIC_KEY, publicKey: epk });
          hasSharedKey.current = true;
        } catch (ee) {
          addMessageToHistory(ALL_CHAT_KEY, {
            type: 'error',
            content: '[Error]: Failed share public key.',
          });
        }
      };
      shareKey();
    }
    if (!isLoggedIn || !isConnected) hasSharedKey.current = false;
  }, [isLoggedIn, isConnected, myKeyPairState, addMessageToHistory]);

  // Event Handlers

  // sendData function
  const sendData = (data: { type: ClientMessageType; [key: string]: unknown }) => {
    const s = ws.current;
    const lt = data.type;
    if (s?.readyState === WebSocket.OPEN) {
      try {
        const jd = JSON.stringify(data);
        s.send(jd);
      } catch (e) {
        console.error('[WS] Send failed:', e, 'Data:', data);
        addMessageToHistory(ALL_CHAT_KEY, { type: 'error', content: '[Error]: Failed send data.' });
      }
    } else {
      console.error(`[WS] Cannot send ${lt}: WS not connected.`);
      addMessageToHistory(ALL_CHAT_KEY, { type: 'error', content: '[Error]: Not connected.' });
    }
  };

  // handleLogin
  const handleLogin = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!isConnected) {
      setLoginError('Not connected.');
      return;
    }
    if (!username || !password) {
      setLoginError('Username/password required.');
      return;
    }
    if (!keyPairRef.current) {
      setLoginError('Keys not ready.');
      return;
    }
    setLoginError('');
    setSystemMessage('Logging in...');
    usernameRef.current = username;
    sendData({ type: ClientMessageType.LOGIN, username: username, password: password });
  };

  // sendTextMessageContent
  const sendTextMessageContent = async (content: string) => {
    if (!isLoggedIn || !isConnected || !content.trim()) return;
    if (!keyPairRef.current?.privateKey) {
      addMessageToHistory(currentChatKey, { type: 'error', content: 'Keys missing.' });
      return;
    }
    if (!serverPublicKey) {
      addMessageToHistory(currentChatKey, { type: 'error', content: 'Server key unavailable.' });
      return;
    }
    const clu = usernameRef.current;
    const tc = content.trim();
    try {
      const ak = await generateAesKey();
      const { iv: ivb64, ciphertext: ctb64 } = await encryptAesGcm(
        ak,
        new TextEncoder().encode(tc)
      );
      const akr = await exportAesKeyRaw(ak);
      const ekfsb64 = await encryptRsaOaep(serverPublicKey, base64ToBuffer(akr));
      const pts = { iv: ivb64, encryptedKey: ekfsb64, ciphertext: ctb64 };
      sendData({
        type: ClientMessageType.SEND_MESSAGE,
        recipient: selectedUser || undefined,
        payload: pts,
      });
      addMessageToHistory(selectedUser || ALL_CHAT_KEY, {
        type: 'my_chat',
        content: tc,
        sender: clu,
        isEncrypted: true,
      });
      setInputValue('');
    } catch (e) {
      addMessageToHistory(currentChatKey, {
        type: 'error',
        content: `[Send Error]: ${e instanceof Error ? e.message : 'Unknown'}`,
      });
    }
  };

  // handleSendMessage
  const handleSendMessage = async (e?: React.FormEvent<HTMLFormElement>) => {
    e?.preventDefault();
    const ti = inputValue.trim();
    if (ti && !selectedFile) await sendTextMessageContent(ti);
    else if (selectedFile) handleSendFile();
  };

  // handleLogout
  const handleLogout = () => {
    if (!isLoggedIn) return;
    console.log('[App] Initiating logout...');
    const userToLogout = usernameRef.current;
    // Clear typing timeout if active
    if (typingTimeoutRef.current) clearTimeout(typingTimeoutRef.current);
    typingTimeoutRef.current = null;
    typingSentTimestampRef.current = 0;

    addMessageToHistory(ALL_CHAT_KEY, { type: 'system', content: '[Logging out...]' });
    if (ws.current?.readyState === WebSocket.OPEN) {
      sendData({ type: ClientMessageType.LOGOUT, username: userToLogout });
    }
    // Reset state
    setIsLoggedIn(false);
    setCurrentUsername('');
    usernameRef.current = '';
    setUsers([]);
    setSelectedUser(null);
    setInputValue('');
    setPeerPublicKeys(new Map());
    setServerPublicKey(null);
    hasSharedKey.current = false;
    setIsConnected(false);
    setSystemMessage('Logged out.');
    setLoginError('');
    setIncomingFileRequests(new Map());
    sendingFiles.current.clear();
    receivingFiles.current.clear();
    setTransferProgress({});
    setChatHistories({ [ALL_CHAT_KEY]: [] }); // Reset history
    setTypingUsers({}); // Reset typing indicators

    if (ws.current) {
      try {
        if (reconnectTimeoutId.current) clearTimeout(reconnectTimeoutId.current);
        ws.current.close(1000, 'User logged out');
        ws.current = null;
      } catch (e) {}
    }
  };

  const handleUsernameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setUsername(e.target.value);
  };
  const handlePasswordChange = (e: React.ChangeEvent<HTMLInputElement>) =>
    setPassword(e.target.value);

  // Typing Indicator Logic
  const sendStopTyping = useCallback(() => {
    sendData({ type: ClientMessageType.STOP_TYPING, recipient: selectedUser || undefined });
    typingSentTimestampRef.current = 0; // Allow sending START_TYPING again
    typingTimeoutRef.current = null;
  }, [selectedUser]); // Recreate if selectedUser changes

  // Handles text input change
  const handleInputChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInputValue(e.target.value);

    const now = Date.now();
    // Throttle START_TYPING message
    if (now - typingSentTimestampRef.current > TYPING_THROTTLE_MS) {
      sendData({ type: ClientMessageType.START_TYPING, recipient: selectedUser || undefined });
      typingSentTimestampRef.current = now;
    }

    // Debounce STOP_TYPING message
    if (typingTimeoutRef.current) {
      clearTimeout(typingTimeoutRef.current);
    }
    typingTimeoutRef.current = setTimeout(sendStopTyping, TYPING_TIMEOUT_MS);
  };

  // Handle input blur
  const handleInputBlur = () => {
    if (typingTimeoutRef.current) {
      clearTimeout(typingTimeoutRef.current);
    }
    // Send STOP_TYPING immediately on blur if user was typing
    if (typingSentTimestampRef.current !== 0) {
      sendStopTyping();
    }
  };

  // handleKeyDown
  const handleKeyDown = (event: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === 'Enter') {
      if (!event.shiftKey) {
        event.preventDefault();
        // Clear timeout and send STOP_TYPING before sending message
        if (typingTimeoutRef.current) clearTimeout(typingTimeoutRef.current);
        if (typingSentTimestampRef.current !== 0) sendStopTyping(); // Send stop if was typing
        handleSendMessage();
      }
      // Allow Shift+Enter for newline without affecting typing indicator much
    }
  };

  const handleUserSelect = (user: string) => {
    const clu = usernameRef.current;
    if (user !== clu) {
      setSelectedUser(user);
      if (isLoggedIn && !peerPublicKeys.has(user)) {
        sendData({ type: ClientMessageType.REQUEST_PUBLIC_KEY, username: user });
      }
    }
  };
  const handleSelectMainChat = () => setSelectedUser(null);
  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const f = event.target.files?.[0];
    if (f) {
      if (f.size > MAX_FILE_SIZE) {
        addMessageToHistory(currentChatKey, { type: 'error', content: `File too large.` });
        setSelectedFile(null);
      } else {
        setSelectedFile(f);
      }
      if (fileInputRef.current) fileInputRef.current.value = '';
    } else {
      setSelectedFile(null);
    }
  };
  const handleSendFile = async () => {
    if (!selectedFile || !selectedUser || !isLoggedIn || !isConnected) {
      addMessageToHistory(currentChatKey, { type: 'error', content: 'Cannot send file.' });
      return;
    }
    if (!keyPairRef.current?.privateKey) {
      addMessageToHistory(selectedUser, { type: 'error', content: 'Keys missing.' });
      return;
    }
    const rpk = peerPublicKeys.get(selectedUser);
    if (!rpk) {
      addMessageToHistory(selectedUser, {
        type: 'system',
        content: `Recipient key needed. Requesting...`,
      });
      sendData({ type: ClientMessageType.REQUEST_PUBLIC_KEY, username: selectedUser });
      return;
    }
    const f = selectedFile;
    const tid = generateUniqueId();
    addMessageToHistory(selectedUser, {
      type: 'file_notice',
      content: `Initiating transfer: ${f.name}`,
      transferId: tid,
    });
    setSelectedFile(null);
    try {
      const ak = await generateAesKey();
      const akr = await exportAesKeyRaw(ak);
      const ekb64 = await encryptRsaOaep(rpk, base64ToBuffer(akr));
      const fb = await f.arrayBuffer();
      const { iv: ivb64, ciphertext: ecb64 } = await encryptAesGcm(ak, fb);
      const ecb = base64ToBuffer(ecb64);
      const fi: FileInfo = {
        name: f.name,
        size: f.size,
        type: f.type || 'application/octet-stream',
        iv: ivb64,
        encryptedKey: ekb64,
      };
      const tc = Math.ceil(ecb.byteLength / CHUNK_SIZE);
      const ss: SendingFileState = {
        file: f,
        encryptedContent: ecb,
        recipient: selectedUser,
        fileInfo: fi,
        totalChunks: tc,
        nextChunkIndex: 0,
        status: 'pending_accept',
      };
      sendingFiles.current.set(tid, ss);
      setTransferProgress((p) => ({ ...p, [tid]: 0 }));
      sendData({
        type: ClientMessageType.FILE_TRANSFER_REQUEST,
        recipient: selectedUser,
        fileInfo: fi,
      });
    } catch (e) {
      console.error(`[ERROR] Failed initiate transfer ${tid}:`, e);
      addMessageToHistory(selectedUser, {
        type: 'error',
        content: `Failed start transfer: ${e instanceof Error ? e.message : 'Unknown'}`,
        transferId: tid,
      });
      sendingFiles.current.delete(tid);
      setTransferProgress((p) => {
        const n = { ...p };
        delete n[tid];
        return n;
      });
    }
  };
  const sendChunk = (transferId: string, state: SendingFileState) => {
    if (!state.encryptedContent || state.status !== 'sending') {
      if (state.status !== 'complete' && state.status !== 'rejected') {
        sendingFiles.current.delete(transferId);
        setTransferProgress((p) => {
          const n = { ...p };
          delete n[transferId];
          return n;
        });
        addMessageToHistory(state.recipient, {
          type: 'error',
          content: `Transfer failed internally.`,
          transferId,
        });
      }
      return;
    }
    if (!ws.current || ws.current.readyState !== WebSocket.OPEN) {
      state.status = 'error';
      addMessageToHistory(state.recipient, {
        type: 'error',
        content: `Transfer failed: Connection lost.`,
        transferId,
      });
      setTransferProgress((p) => ({ ...p, [transferId]: -1 }));
      return;
    }
    const s = state.nextChunkIndex * CHUNK_SIZE;
    const e = Math.min(s + CHUNK_SIZE, state.encryptedContent.byteLength);
    const c = state.encryptedContent.slice(s, e);
    const ilc = e >= state.encryptedContent.byteLength;
    sendData({
      type: ClientMessageType.FILE_CHUNK,
      recipient: state.recipient,
      fileInfo: { name: state.fileInfo.name },
      chunkData: bufferToBase64(c),
      chunkIndex: state.nextChunkIndex,
      isLastChunk: ilc,
    });
    state.nextChunkIndex++;
    const pr = Math.round((state.nextChunkIndex / state.totalChunks) * 100);
    setTransferProgress((p) => ({ ...p, [transferId]: pr }));
    if (ilc) {
      state.status = 'complete';
      addMessageToHistory(state.recipient, {
        type: 'file_notice',
        content: `File sent: ${state.fileInfo.name}`,
        transferId,
      });
    } else {
      setTimeout(() => {
        if (
          sendingFiles.current.has(transferId) &&
          sendingFiles.current.get(transferId)?.status === 'sending'
        )
          sendChunk(transferId, state);
      }, 10);
    }
  };
  const handleAcceptFile = async (transferId: string) => {
    const r = incomingFileRequests.get(transferId);
    if (!r) return;
    if (!keyPairRef.current?.privateKey) {
      addMessageToHistory(r.sender, {
        type: 'error',
        content: 'Cannot accept: Keys missing.',
        transferId,
      });
      return;
    }
    const { sender, fileInfo } = r;
    try {
      const akb = await decryptRsaOaep(keyPairRef.current.privateKey, fileInfo.encryptedKey);
      const ak = await importAesKeyRaw(bufferToBase64(akb));
      const rs: ReceivingFileState = {
        id: transferId,
        sender,
        fileInfo,
        aesKey: ak,
        chunks: [],
        receivedBytes: 0,
        status: 'receiving',
      };
      receivingFiles.current.set(transferId, rs);
      setTransferProgress((p) => ({ ...p, [transferId]: 0 }));
      setIncomingFileRequests((p) => {
        const n = new Map(p);
        n.delete(transferId);
        return n;
      });
      sendData({
        type: ClientMessageType.FILE_TRANSFER_ACCEPT,
        sender,
        fileInfo: { name: fileInfo.name, size: fileInfo.size },
      });
      addMessageToHistory(sender, {
        type: 'file_notice',
        content: `Accepted file: ${fileInfo.name}. Receiving...`,
        transferId,
      });
    } catch (e) {
      addMessageToHistory(sender, {
        type: 'error',
        content: `Accept failed: ${e instanceof Error ? e.message : 'Error'}`,
        transferId,
      });
      setIncomingFileRequests((p) => {
        const n = new Map(p);
        n.delete(transferId);
        return n;
      });
    }
  };
  const handleRejectFile = (transferId: string) => {
    const r = incomingFileRequests.get(transferId);
    if (!r) return;
    const { sender, fileInfo } = r;
    setIncomingFileRequests((p) => {
      const n = new Map(p);
      n.delete(transferId);
      return n;
    });
    sendData({
      type: ClientMessageType.FILE_TRANSFER_REJECT,
      sender,
      fileInfo: { name: fileInfo.name },
    });
    addMessageToHistory(sender, {
      type: 'file_notice',
      content: `Rejected file: ${fileInfo.name}`,
      transferId,
    });
  };
  const handleDownloadFile = (objectUrl: string | undefined, filename: string | undefined) => {
    if (!objectUrl || !filename) return;
    const a = document.createElement('a');
    a.href = objectUrl;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };
  const handleEmojiSelect = (emojiData: EmojiClickData) => {
    const em = emojiData.emoji;
    const i = messageInputRef.current;
    if (i) {
      const s = i.selectionStart ?? inputValue.length;
      const e = i.selectionEnd ?? inputValue.length;
      const nv = inputValue.substring(0, s) + em + inputValue.substring(e);
      setInputValue(nv);
      i.focus();
      setTimeout(() => {
        i.selectionStart = i.selectionEnd = s + em.length;
      }, 0);
    } else {
      setInputValue((p) => p + em);
    }
    setShowEmojiPicker(false);
  };

  // Derived State for UI rendering
  const currentMessages = chatHistories[currentChatKey] || [];
  // Combine online users and users with history for the sidebar list
  const displayablePeers = Array.from(
    new Set([
      ...users.filter((u) => u !== currentUsername),
      ...Object.keys(chatHistories).filter(
        (key) => key !== ALL_CHAT_KEY && key !== currentUsername
      ), // Add users from history (excluding self and All Chat)
    ])
  );
  const fileTransferReady = selectedUser ? peerPublicKeys.has(selectedUser) : false;
  // Get users currently typing in the active chat context
  const usersTypingInCurrentChat = Array.from(typingUsers[currentChatKey] || []);

  // Render UI
  return (
    <div className="flex flex-col h-screen bg-gradient-to-br from-blue-100 via-purple-100 to-pink-100 p-4 gap-4 font-sans">
      {/* Header (Unchanged) */}
      <header className="text-center py-2">
        <h1 className="text-2xl font-bold text-gray-800">Secure Chat</h1>
        <div className="text-sm text-gray-600 mt-1 flex items-center justify-center gap-x-2 flex-wrap">
          <span>
            {' '}
            Status:{' '}
            {isConnected ? (
              <span className="text-green-600 font-semibold">Connected</span>
            ) : (
              <span className="text-red-600 font-semibold">Disconnected</span>
            )}{' '}
          </span>
          {isLoggedIn && currentUsername && (
            <span className="border-l pl-2">
              User: <span className="font-semibold">{currentUsername}</span>
            </span>
          )}
          {systemMessage && !loginError && (
            <span className="text-yellow-600 italic">({systemMessage})</span>
          )}
          {!keyPairRef.current && !isLoggedIn && (
            <span className="text-orange-600 font-semibold">(Generating keys...)</span>
          )}
          {isLoggedIn && !serverPublicKey && (
            <span className="text-orange-600 font-semibold">(Waiting for server key...)</span>
          )}
        </div>
      </header>

      {/* Main Layout */}
      <div className="flex flex-1 gap-4 overflow-hidden">
        {/* Sidebar (MODIFIED - Iterates over displayablePeers) */}
        <Card className="w-60 flex flex-col bg-white/80 backdrop-blur-sm border-gray-200 shadow-md rounded-lg">
          <CardHeader className="p-3 border-b bg-gray-50/80 rounded-t-lg">
            <CardTitle className="text-lg text-gray-700">Conversations</CardTitle>
          </CardHeader>
          <CardContent className="flex-1 p-0">
            <ScrollArea className="h-full w-full p-2">
              {/* All Chat Button */}
              <Button
                variant={!selectedUser ? 'secondary' : 'ghost'}
                className="w-full justify-start gap-2 mb-2 text-sm"
                onClick={handleSelectMainChat}
                disabled={!isLoggedIn}
                title="Switch to All Chat (Broadcast)"
              >
                {' '}
                <Users className="h-5 w-5 text-gray-600" />{' '}
                <span className="font-medium">All Chat</span>{' '}
              </Button>
              <hr className="my-2 border-gray-200" />
              {/* Conversation List */}
              <ul className="space-y-1">
                {/* Iterate over combined list of online users and users with history */}
                {displayablePeers.map((peerUsername) => {
                  // Check if this peer is currently online using the `users` state
                  const isOnline = users.includes(peerUsername);
                  return (
                    <li key={peerUsername}>
                      <Button
                        variant={selectedUser === peerUsername ? 'secondary' : 'ghost'}
                        className="w-full justify-start gap-2 text-sm h-9"
                        onClick={() => handleUserSelect(peerUsername)}
                        disabled={!isLoggedIn}
                        title={`Chat with ${peerUsername}${isOnline ? ' (Online)' : ' (Offline)'}`}
                      >
                        <span className="flex items-center gap-1.5 grow overflow-hidden">
                          {/* Show online indicator conditionally */}
                          <Circle
                            className={`h-2.5 w-2.5 ${
                              isOnline ? 'text-green-500' : 'text-gray-400'
                            } fill-current shrink-0`}
                          />
                          <User
                            className={`h-5 w-5 ${
                              selectedUser === peerUsername ? 'text-blue-700' : 'text-gray-500'
                            } shrink-0`}
                          />
                          <span
                            className={`truncate font-medium ${
                              selectedUser === peerUsername ? 'text-blue-700' : 'text-gray-700'
                            }`}
                          >
                            {peerUsername}
                          </span>
                        </span>
                        {/* Lock icon indicates if key is available (needed for file transfer) */}
                        {peerPublicKeys.has(peerUsername) ? (
                          <Lock
                            size={14}
                            className="ml-auto text-blue-500 shrink-0"
                            title="Ready for File Transfers"
                          />
                        ) : (
                          <Unlock
                            size={14}
                            className="ml-auto text-gray-400 shrink-0"
                            title="Key Missing for File Transfers"
                          />
                        )}
                      </Button>
                    </li>
                  );
                })}
                {/* Optional: Message if no private conversations exist yet */}
                {isLoggedIn && displayablePeers.length === 0 && (
                  <li className="text-gray-500 italic text-center p-2 text-xs">
                    No private chats yet
                  </li>
                )}
                {!isLoggedIn && (
                  <li className="text-gray-500 italic text-center p-2 text-xs">
                    Log in to see chats
                  </li>
                )}
              </ul>
            </ScrollArea>
          </CardContent>
        </Card>

        {/* Chat Area */}
        <Card className="flex-1 flex flex-col bg-white/80 backdrop-blur-sm border-gray-200 shadow-md rounded-lg overflow-hidden">
          {/* Chat Header (Unchanged) */}
          <CardHeader className="p-3 border-b bg-gray-50/80 rounded-t-lg">
            <div className="flex justify-between items-center">
              <div className="flex items-center gap-2">
                {' '}
                <CardTitle className="text-lg text-gray-700">
                  {' '}
                  {selectedUser ? `Chat with ${selectedUser}` : 'All Chat'}{' '}
                </CardTitle>{' '}
              </div>
              {selectedUser && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={handleSelectMainChat}
                  className="text-xs text-blue-600 hover:text-blue-800"
                  title="Back to All Chat"
                >
                  {' '}
                  <X className="h-4 w-4 mr-1" /> Back to All{' '}
                </Button>
              )}
            </div>
          </CardHeader>

          <CardContent className="flex-1 p-0 overflow-hidden">
            <ScrollArea className="h-full w-full p-4">
              {isHistoryLoading && isLoggedIn && (
                <div className="text-center text-sm text-gray-500 italic p-4">
                  Loading history...
                </div>
              )}
              <div className="space-y-3">
                {currentMessages.map((msg, index) => {
                  const messageKey = msg.transferId
                    ? `${msg.transferId}-${msg.type}-${index}`
                    : msg.timestamp
                    ? `${msg.timestamp}-${index}`
                    : `msg-${index}`;
                  // File Transfer Messages (Non-persisted)
                  if (msg.type === 'file_request' && msg.transferId && msg.fileInfo) {
                    const r = incomingFileRequests.get(msg.transferId);
                    if (!r) return null;
                    return (
                      <Alert
                        key={messageKey}
                        variant="default"
                        className="bg-blue-50 border-blue-200"
                      >
                        {' '}
                        <FileIcon className="h-4 w-4" />{' '}
                        <AlertTitle className="font-semibold">
                          Incoming File from {msg.sender}
                        </AlertTitle>{' '}
                        <AlertDescription className="text-sm">
                          {' '}
                          <p className="mb-2">
                            {' '}
                            User <span className="font-medium">{msg.sender}</span> wants to send you{' '}
                            <span className="font-medium">{msg.fileInfo.name}</span> ({' '}
                            {(msg.fileInfo.size / 1024 / 1024).toFixed(2)} MB).{' '}
                          </p>{' '}
                          <div className="flex gap-2 mt-2">
                            {' '}
                            <Button
                              size="sm"
                              variant="default"
                              onClick={() => handleAcceptFile(msg.transferId!)}
                            >
                              {' '}
                              <Check className="h-4 w-4 mr-1" /> Accept{' '}
                            </Button>{' '}
                            <Button
                              size="sm"
                              variant="destructive"
                              onClick={() => handleRejectFile(msg.transferId!)}
                            >
                              {' '}
                              <X className="h-4 w-4 mr-1" /> Reject{' '}
                            </Button>{' '}
                          </div>{' '}
                        </AlertDescription>{' '}
                      </Alert>
                    );
                  }
                  if (msg.type === 'file_notice') {
                    const p = transferProgress[msg.transferId!] ?? null;
                    const iS = sendingFiles.current.has(msg.transferId!);
                    const iR = receivingFiles.current.has(msg.transferId!);
                    const st = typeof msg.content === 'string' ? msg.content : 'File Notice';
                    return (
                      <Alert
                        key={messageKey}
                        variant="default"
                        className="bg-gray-50 border-gray-200 text-xs"
                      >
                        {' '}
                        <FileIcon className="h-4 w-4" />{' '}
                        <AlertDescription>
                          {' '}
                          {st}{' '}
                          {(iS || iR) && p !== null && p >= 0 && p <= 100 && (
                            <Progress value={p} className="w-full h-2 mt-1" />
                          )}{' '}
                        </AlertDescription>{' '}
                      </Alert>
                    );
                  }
                  if (msg.type === 'file_image' && msg.objectUrl && msg.fileInfo) {
                    return (
                      <div
                        key={messageKey}
                        className={`flex flex-col ${
                          msg.sender === currentUsername ? 'items-end' : 'items-start'
                        }`}
                      >
                        {' '}
                        <div className="p-2 border rounded-lg bg-gray-100 max-w-xs md:max-w-sm">
                          {' '}
                          <p className="text-xs font-semibold mb-1 text-gray-700">
                            {msg.sender}
                          </p>{' '}
                          <img
                            src={msg.objectUrl}
                            alt={`Image from ${msg.sender}: ${msg.fileInfo.name}`}
                            className="max-w-full h-auto rounded block object-contain bg-white"
                          />{' '}
                          <div className="flex justify-between items-center mt-2">
                            {' '}
                            <span
                              className="text-xs text-gray-600 truncate"
                              title={msg.fileInfo.name}
                            >
                              {' '}
                              {msg.fileInfo.name}{' '}
                            </span>{' '}
                            <Button
                              size="sm"
                              variant="outline"
                              className="h-7 px-2 text-xs"
                              onClick={() => handleDownloadFile(msg.objectUrl, msg.fileInfo?.name)}
                            >
                              {' '}
                              <Download className="h-3 w-3 mr-1" /> Download{' '}
                            </Button>{' '}
                          </div>{' '}
                        </div>{' '}
                      </div>
                    );
                  }
                  // Persisted/Live Text Messages
                  if (
                    msg.type === 'my_chat' ||
                    msg.type === 'chat' ||
                    msg.type === 'system' ||
                    msg.type === 'error'
                  ) {
                    const cs = typeof msg.content === 'string' ? msg.content : '';
                    let rc: React.ReactNode = <div className="chat-content">{cs}</div>;
                    if ((msg.type === 'chat' || msg.type === 'my_chat') && cs) {
                      try {
                        const ph = marked.parse(cs, { breaks: true });
                        const sh = DOMPurify.sanitize(ph);
                        rc = (
                          <div
                            className="chat-content prose prose-sm max-w-none"
                            dangerouslySetInnerHTML={{ __html: sh || '' }}
                          />
                        );
                      } catch (e) {
                        rc = <div className="chat-content whitespace-pre-wrap">{cs}</div>;
                      }
                    } else {
                      rc = <div className="chat-content whitespace-pre-wrap">{cs}</div>;
                    }
                    if (msg.type === 'my_chat' || msg.type === 'chat') {
                      return (
                        <div
                          key={messageKey}
                          className={`flex flex-col ${
                            msg.type === 'my_chat' ? 'items-end' : 'items-start'
                          }`}
                        >
                          {' '}
                          <div
                            className={`max-w-xs md:max-w-md lg:max-w-lg rounded-lg px-3 py-2 shadow-sm text-sm ${
                              msg.type === 'my_chat'
                                ? 'bg-blue-600 text-white'
                                : 'bg-gray-100 text-gray-900'
                            }`}
                          >
                            {' '}
                            {msg.sender && msg.type !== 'my_chat' && (
                              <p className="text-xs font-semibold mb-0.5 text-gray-700">
                                {msg.sender}
                              </p>
                            )}{' '}
                            {rc}{' '}
                          </div>{' '}
                        </div>
                      );
                    } else {
                      return (
                        <div key={messageKey} className={`flex flex-col items-center w-full`}>
                          {' '}
                          <div
                            className={`max-w-full rounded-lg px-3 py-1 break-words shadow-none text-xs text-center ${
                              msg.type === 'error'
                                ? 'bg-red-100 text-red-700 italic'
                                : 'text-gray-500 italic bg-transparent'
                            }`}
                          >
                            {' '}
                            {rc}{' '}
                          </div>{' '}
                        </div>
                      );
                    }
                  }
                  return null;
                })}
                <div ref={messagesEndRef} />
              </div>
            </ScrollArea>
          </CardContent>

          {/* Input Area  */}
          <CardFooter className="p-4 border-t bg-gray-50/80">
            {!isLoggedIn ? (
              /* Login Form */ <form onSubmit={handleLogin} className="w-full space-y-3">
                {' '}
                <h3 className="text-center font-medium text-gray-700">Please Log In</h3>{' '}
                {loginError && <p className="text-red-500 text-sm text-center">{loginError}</p>}{' '}
                {systemMessage && !loginError && (
                  <p className="text-yellow-600 text-sm text-center">{systemMessage}</p>
                )}{' '}
                <div className="flex flex-col sm:flex-row gap-2">
                  {' '}
                  <Input
                    type="text"
                    placeholder="Username"
                    value={username}
                    onChange={handleUsernameChange}
                    disabled={!isConnected || !keyPairRef.current}
                    aria-label="Username"
                    className="flex-1"
                    autoComplete="username"
                    required
                  />{' '}
                  <Input
                    type="password"
                    placeholder="Password"
                    value={password}
                    onChange={handlePasswordChange}
                    disabled={!isConnected || !keyPairRef.current}
                    aria-label="Password"
                    className="flex-1"
                    autoComplete="current-password"
                    required
                  />{' '}
                </div>{' '}
                <Button
                  type="submit"
                  disabled={
                    !isConnected ||
                    !keyPairRef.current ||
                    !!systemMessage.match(/Logging in|Connecting/)
                  }
                  className="w-full"
                >
                  {' '}
                  {!keyPairRef.current
                    ? 'Generating Keys...'
                    : !isConnected
                    ? 'Connecting...'
                    : 'Login / Register'}{' '}
                </Button>{' '}
              </form>
            ) : (
              /* Message Input Form Area */
              <div className="w-full">
                {/* Typing Indicator Area */}
                <div className="h-5 mb-1 text-xs text-gray-500 italic px-1 truncate">
                  {usersTypingInCurrentChat.length > 0 && (
                    <span>
                      {usersTypingInCurrentChat.slice(0, 3).join(', ')}
                      {usersTypingInCurrentChat.length > 3 ? ' and others' : ''}
                      {usersTypingInCurrentChat.length === 1 ? ' is' : ' are'} typing...
                    </span>
                  )}
                </div>
                {/* Input Controls */}
                <div className="w-full flex items-end gap-2 relative">
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    title="Attach file (Private chat only)"
                    disabled={!selectedUser || !fileTransferReady}
                    onClick={() => fileInputRef.current?.click()}
                    className={`shrink-0 ${
                      !selectedUser || !fileTransferReady ? 'text-gray-400 cursor-not-allowed' : ''
                    }`}
                  >
                    {' '}
                    <Paperclip className="h-5 w-5" />{' '}
                  </Button>
                  <input
                    type="file"
                    ref={fileInputRef}
                    onChange={handleFileChange}
                    className="hidden"
                    disabled={!selectedUser || !fileTransferReady}
                  />
                  {selectedFile && selectedUser ? (
                    <div className="flex items-center gap-2 flex-1 bg-gray-100 p-1 rounded-md border h-10">
                      {' '}
                      <FileIcon className="h-4 w-4 text-gray-600 shrink-0 ml-1" />{' '}
                      <span
                        className="text-sm text-gray-700 truncate flex-1"
                        title={selectedFile.name}
                      >
                        {' '}
                        {selectedFile.name} ({(selectedFile.size / 1024).toFixed(1)} KB){' '}
                      </span>{' '}
                      <Button
                        type="button"
                        size="icon"
                        variant="ghost"
                        className="h-6 w-6 shrink-0"
                        onClick={() => setSelectedFile(null)}
                        title="Cancel file selection"
                      >
                        {' '}
                        <Trash2 className="h-4 w-4 text-red-500" />{' '}
                      </Button>{' '}
                      <Button
                        type="button"
                        size="sm"
                        className="h-7 shrink-0"
                        onClick={handleSendFile}
                        title={`Send file to ${selectedUser}`}
                        disabled={!fileTransferReady}
                      >
                        {' '}
                        <Upload className="h-4 w-4 mr-1" /> Send{' '}
                      </Button>{' '}
                    </div>
                  ) : (
                    <div className="flex-1 relative flex items-center">
                      <TextareaAutosize
                        ref={messageInputRef}
                        placeholder={
                          selectedUser
                            ? `Send message to ${selectedUser}...`
                            : `Send broadcast message...`
                        }
                        value={inputValue}
                        onChange={handleInputChange}
                        onKeyDown={handleKeyDown}
                        onBlur={handleInputBlur}
                        aria-label="Chat message input"
                        className="pr-10 flex-1 resize-none border rounded-md shadow-sm focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500 p-2 leading-tight text-sm"
                        minRows={1}
                        maxRows={5}
                        disabled={!isConnected || !serverPublicKey}
                        autoComplete="off"
                      />
                      {/* Emoji Picker  */}
                      <Popover open={showEmojiPicker} onOpenChange={setShowEmojiPicker}>
                        <PopoverTrigger
                          className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7 p-0 inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50 text-gray-500 hover:bg-accent hover:text-accent-foreground" // Styles copied from Button variant=ghost, size=icon
                          title="Select emoji"
                        >
                          {/* Icon is now the direct child */}
                          <Smile className="h-5 w-5" />
                        </PopoverTrigger>
                        <PopoverContent className="w-auto p-0 mb-1" side="top" align="end">
                          <EmojiPicker
                            onEmojiClick={handleEmojiSelect}
                            autoFocusSearch={false}
                            height={400}
                            lazyLoadEmojis={true}
                            theme={EmojiTheme.AUTO}
                          />
                        </PopoverContent>
                      </Popover>
                    </div>
                  )}
                  {!selectedFile && (
                    <Button
                      type="button"
                      onClick={() => handleSendMessage()}
                      size="icon"
                      aria-label="Send message"
                      title={selectedUser ? 'Send Private Message' : 'Send Broadcast Message'}
                      disabled={!inputValue.trim() || !isConnected || !serverPublicKey}
                      className="shrink-0"
                    >
                      {' '}
                      <SendHorizonal className="h-4 w-4" />{' '}
                    </Button>
                  )}
                  <Button
                    type="button"
                    variant="destructive"
                    size="icon"
                    onClick={handleLogout}
                    aria-label="Logout"
                    title="Logout"
                    disabled={!isLoggedIn}
                    className="shrink-0"
                  >
                    {' '}
                    <LogOut className="h-4 w-4" />{' '}
                  </Button>
                </div>
              </div>
            )}
          </CardFooter>
        </Card>
      </div>
    </div>
  );
}

export default App;
