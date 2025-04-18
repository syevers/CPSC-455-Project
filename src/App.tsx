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
//  WebSocket Setup
const SERVER_URL = 'wss://127.0.0.1:8080';

// Crypto Helper Functions
const bufferToBase64 = (buffer: ArrayBuffer): string => {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
};
const base64ToBuffer = (base64: string): ArrayBuffer => {
  const binary_string = atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
};
const generateRsaKeyPair = async (): Promise<CryptoKeyPair> => {
  console.log('Generating Client RSA-OAEP 4096 key pair...');
  const keyPair = await crypto.subtle.generateKey(
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
  return keyPair;
};
// Export user's public key as SPKI Base64
const exportPublicKey = async (key: CryptoKey): Promise<string> => {
  const exportedSpki = await crypto.subtle.exportKey('spki', key);
  return bufferToBase64(exportedSpki);
};
// Function to import PEM public key (needed for server key)
const importPublicKeyPem = async (pem: string): Promise<CryptoKey> => {
  const pemHeader = '-----BEGIN PUBLIC KEY-----';
  const pemFooter = '-----END PUBLIC KEY-----';
  // Remove headers/footers and line breaks
  const pemContents = pem
    .substring(pemHeader.length, pem.length - pemFooter.length - 1)
    .replace(/\s+/g, '');
  // Base64 decode the string to get DER buffer
  const binaryDer = base64ToBuffer(pemContents);
  // Import the key
  return await crypto.subtle.importKey(
    'spki', // SubjectPublicKeyInfo format
    binaryDer,
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256',
    },
    true, // Extractable
    ['encrypt'] // Key usage
  );
};
// Import user's public key
const importUserPublicKey = async (base64Key: string): Promise<CryptoKey> => {
  const spkiBuffer = base64ToBuffer(base64Key);
  return await crypto.subtle.importKey(
    'spki',
    spkiBuffer,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['encrypt']
  );
};
const generateAesKey = async (): Promise<CryptoKey> => {
  return await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ]);
};
const exportAesKeyRaw = async (key: CryptoKey): Promise<string> => {
  const exportedRaw = await crypto.subtle.exportKey('raw', key);
  return bufferToBase64(exportedRaw);
};
const importAesKeyRaw = async (base64Key: string): Promise<CryptoKey> => {
  const rawBuffer = base64ToBuffer(base64Key);
  return await crypto.subtle.importKey('raw', rawBuffer, { name: 'AES-GCM' }, true, [
    'encrypt',
    'decrypt',
  ]);
};
const encryptAesGcm = async (
  key: CryptoKey,
  data: ArrayBuffer
): Promise<{ iv: string; ciphertext: string }> => {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertextBuffer = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, data);
  return { iv: bufferToBase64(iv), ciphertext: bufferToBase64(ciphertextBuffer) };
};
const decryptAesGcm = async (
  key: CryptoKey,
  ivBase64: string,
  ciphertextBase64: string
): Promise<ArrayBuffer> => {
  const iv = base64ToBuffer(ivBase64);
  const ciphertext = base64ToBuffer(ciphertextBase64);
  try {
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      ciphertext
    );
    return decryptedBuffer;
  } catch (error) {
    console.error('AES-GCM Decryption failed:', error);
    throw new Error('AES Decryption Failed');
  }
};
// Encrypt with RSA (used for AES key encryption with server or recipient key)
const encryptRsaOaep = async (publicKey: CryptoKey, data: ArrayBuffer): Promise<string> => {
  const encryptedBuffer = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, data);
  return bufferToBase64(encryptedBuffer);
};
// Decrypt with RSA (used for AES key decryption with own private key)
const decryptRsaOaep = async (privateKey: CryptoKey, base64Data: string): Promise<ArrayBuffer> => {
  const encryptedBuffer = base64ToBuffer(base64Data);
  try {
    return await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, encryptedBuffer);
  } catch (error) {
    console.error('RSA-OAEP Decryption failed:', error);
    throw new Error('RSA Decryption Failed');
  }
};

//  Message Types
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
} // User's public key (SPKI Base64)
interface PingMessage extends ServerMessageBase {
  type: ServerMessageType.PING;
}
interface ServerPublicKeyMessage extends ServerMessageBase {
  type: ServerMessageType.SERVER_PUBLIC_KEY;
  publicKey: string;
} // Server's public key (PEM)

// Message received from Server
interface ServerReceiveMessage extends ServerMessageBase {
  type: ServerMessageType.RECEIVE_MESSAGE;
  sender: string;
  isBroadcast: boolean;
  payload: {
    iv: string; // AES IV (base64)
    encryptedKey: string; // AES key encrypted with public key (base64)
    ciphertext: string; // Message content encrypted with AES key (base64)
  };
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

type ServerMessage =
  | SystemMessage
  | UserListMessage
  | ReceivePublicKeyMessage // User key
  | ServerPublicKeyMessage // Server key
  | ServerReceiveMessage // Encrypted message from server
  | PingMessage
  | IncomingFileRequestMessage
  | FileAcceptNoticeMessage
  | FileRejectNoticeMessage
  | FileChunkReceiveMessage;

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
const ALL_CHAT_KEY = 'All Chat';

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
  const [users, setUsers] = useState<string[]>([]);
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
  const hasSharedKey = useRef<boolean>(false); // User sharing their key
  const keyPairRef = useRef<CryptoKeyPair | null>(null); // User's key pair
  const [myKeyPairState, setMyKeyPairState] = useState<CryptoKeyPair | null>(null);
  // Store peer keys as CryptoKey objects, imported from SPKI Base64
  const [peerPublicKeys, setPeerPublicKeys] = useState<Map<string, CryptoKey>>(new Map());
  // Stores imported server public key
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

  // Effects
  const currentChatKey = selectedUser ?? ALL_CHAT_KEY;
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [chatHistories, currentChatKey]);
  const addMessageToHistory = useCallback(
    (peerKey: string, message: Omit<DisplayMessage, 'timestamp'>) => {
      if (!isMounted.current) {
        return;
      }
      const newMessage = { ...message, timestamp: Date.now() };
      setChatHistories((prev) => {
        const history = prev[peerKey] || [];
        if (
          newMessage.transferId &&
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
    console.log('RSA Key Gen Effect - Mounting');
    const setupCrypto = async () => {
      try {
        const keys = await generateRsaKeyPair();
        if (isMounted.current) {
          setMyKeyPairState(keys);
          keyPairRef.current = keys;
          console.log('Client RSA key pair generated and stored.');
        }
      } catch (error) {
        console.error('Client RSA key generation failed:', error);
        if (isMounted.current) {
          setLoginError('CRITICAL: Cannot generate keys. Please refresh.');
        }
      }
    };
    setupCrypto();
    return () => {
      console.log('RSA Key Gen Effect - Unmounting');
      isMounted.current = false;
    };
  }, []);

  // WebSocket Connection and Message Handling Effect
  useEffect(() => {
    let isEffectMounted = true;
    let localWsInstance: WebSocket | null = null;

    const connect = () => {
      if (isConnecting.current || (ws.current && ws.current.readyState === WebSocket.OPEN)) {
        return;
      }
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
        console.warn('[WS] ws.current not null before new connection. Cleaning up stale instance.');
        ws.current.onopen = null;
        ws.current.onclose = null;
        ws.current.onerror = null;
        ws.current.onmessage = null;
        if (
          ws.current.readyState === WebSocket.OPEN ||
          ws.current.readyState === WebSocket.CONNECTING
        ) {
          ws.current.close();
        }
        ws.current = null;
      }
      const currentRunWs = new WebSocket(SERVER_URL);
      localWsInstance = currentRunWs;
      ws.current = currentRunWs;
      console.log('[WS] New WebSocket instance created.');

      currentRunWs.onopen = () => {
        if (ws.current !== currentRunWs || !isEffectMounted) {
          console.log('[WS] onopen ignored: stale instance or unmounted effect.');
          return;
        }
        console.log('[WS] WebSocket Connected (onopen)');
        isConnecting.current = false;
        setIsConnected(true);
        setSystemMessage('');
        setLoginError('');
      };
      currentRunWs.onclose = (event: CloseEvent) => {
        if (localWsInstance !== currentRunWs) {
          console.log(`[WS] onclose ignored: stale instance.`);
          return;
        }
        console.log(
          `[WS] WebSocket Disconnected (onclose). Code: ${event.code}, Reason: ${event.reason}`
        );
        isConnecting.current = false;
        if (ws.current === currentRunWs) {
          ws.current = null;
          console.log('[WS] ws.current nulled due to onclose.');
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
          setSystemMessage('Disconnected. Reconnecting...');
          hasSharedKey.current = false;
          if (reconnectTimeoutId.current) clearTimeout(reconnectTimeoutId.current);
          console.log('[WS] Scheduling reconnection attempt in 5s...');
          reconnectTimeoutId.current = setTimeout(() => {
            if (isEffectMounted && !ws.current && !isConnecting.current) {
              connect();
            } else {
              console.log(
                '[WS] Reconnect attempt skipped (unmounted or already connected/connecting).'
              );
            }
          }, 5000);
        } else {
          console.log('[WS] onclose skipped state updates/reconnect: effect unmounted.');
        }
      };
      currentRunWs.onerror = (event: Event) => {
        if (localWsInstance !== currentRunWs || !isEffectMounted) {
          console.log('[WS] onerror ignored: stale instance or unmounted effect.');
          return;
        }
        console.error('[WS] WebSocket Error:', event);
        isConnecting.current = false;
      };

      // Modified onmessage Handler
      currentRunWs.onmessage = async (event: MessageEvent) => {
        if (ws.current !== currentRunWs || !isEffectMounted) {
          return;
        }

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
              } else if (content.startsWith('Login failed')) {
                setLoginError(content);
                setSystemMessage('');
                setIsLoggedIn(false);
                setCurrentUsername('');
                usernameRef.current = '';
              } else {
                if (!content.startsWith('Public key for user')) {
                  addMessageToHistory(ALL_CHAT_KEY, {
                    type: 'system',
                    content: `[SERVER]: ${content}`,
                  });
                }
              }
              break;
            }
            case ServerMessageType.USER_LIST: {
              const newUsers = message.users ?? [];
              const loggedInUser = usernameRef.current;
              setUsers(newUsers);
              if (selectedUser && !newUsers.includes(selectedUser)) {
                addMessageToHistory(selectedUser, {
                  type: 'system',
                  content: `User ${selectedUser} went offline.`,
                });
                setSelectedUser(null);
              }
              setPeerPublicKeys((prevKeys) => {
                const updatedKeys = new Map(prevKeys);
                let changed = false;
                Array.from(updatedKeys.keys()).forEach((user) => {
                  if (!newUsers.includes(user)) {
                    updatedKeys.delete(user);
                    changed = true;
                  }
                });
                if (loggedInUser) {
                  newUsers.forEach((user) => {
                    if (user !== loggedInUser && !updatedKeys.has(user)) {
                      sendData({ type: ClientMessageType.REQUEST_PUBLIC_KEY, username: user });
                    }
                  });
                }
                return changed ? updatedKeys : prevKeys;
              });
              break;
            }

            // Handle Receiving Server's Public Key
            case ServerMessageType.SERVER_PUBLIC_KEY: {
              try {
                // Import PEM key from server
                const importedKey = await importPublicKeyPem(message.publicKey);
                setServerPublicKey(importedKey);
              } catch (error) {
                console.error('[ERROR] Failed to import server public key:', error);
                setLoginError('Error processing server key. Cannot send messages. Please refresh.');
                if (ws.current) ws.current.close(); // Close connection on critical error
              }
              break;
            }

            // Handle Receiving User's Public Key
            case ServerMessageType.RECEIVE_PUBLIC_KEY: {
              try {
                // Use SPKI import for user keys received from server
                const importedKey = await importUserPublicKey(message.publicKey);
                setPeerPublicKeys((prev) => new Map(prev).set(message.username, importedKey));
                if (selectedUser === message.username) {
                  addMessageToHistory(selectedUser, {
                    type: 'system',
                    content: `Encryption key received for ${selectedUser}. File transfers enabled.`,
                  });
                }
              } catch (importError) {
                console.error(`Failed to import public key for ${message.username}:`, importError);
                addMessageToHistory(message.username, {
                  type: 'error',
                  content: `Received invalid key from ${message.username}. File transfers may fail.`,
                });
              }
              break;
            }

            // Handle Receiving Encrypted Messages from Server
            case ServerMessageType.RECEIVE_MESSAGE: {
              const { sender, isBroadcast, payload } = message;
              const { iv, encryptedKey, ciphertext } = payload;
              const myPrivateKey = keyPairRef.current?.privateKey;

              if (!myPrivateKey) {
                console.error('[ERROR] Cannot decrypt message: Own private key not available.');
                addMessageToHistory(isBroadcast ? ALL_CHAT_KEY : sender, {
                  type: 'error',
                  content: '[Error] Cannot decrypt message: Missing your private key.',
                });
                break;
              }

              try {
                // Decrypt AES key using own private key
                const aesKeyBuffer = await decryptRsaOaep(myPrivateKey, encryptedKey);
                const aesKey = await importAesKeyRaw(bufferToBase64(aesKeyBuffer));
                // Decrypt message content using AES key
                const decryptedContent = await decryptAesGcm(aesKey, iv, ciphertext);
                const decryptedText = new TextDecoder().decode(decryptedContent);
                // Add to history
                addMessageToHistory(isBroadcast ? ALL_CHAT_KEY : sender, {
                  type: 'chat',
                  content: decryptedText,
                  sender: sender,
                  isEncrypted: true,
                }); // Mark as encrypted in transit
              } catch (decryptionError: any) {
                console.error(`Failed to decrypt message from ${sender}:`, decryptionError);
                addMessageToHistory(isBroadcast ? ALL_CHAT_KEY : sender, {
                  type: 'error',
                  content: `[Decryption Failed from ${sender}]`,
                  sender: sender,
                });
              }
              break;
            }

            // PING/PONG
            case ServerMessageType.PING: {
              try {
                sendData({ type: ClientMessageType.PONG });
              } catch (e) {
                console.error('[ERROR] Failed to send PONG response:', e);
              }
              break;
            }

            // File Transfer Handling
            case ServerMessageType.INCOMING_FILE_REQUEST: {
              const { sender, fileInfo } = message;
              const transferId = generateUniqueId();
              const request: FileTransferRequest = {
                id: transferId,
                sender,
                fileInfo,
                timestamp: Date.now(),
              };
              setIncomingFileRequests((prev) => new Map(prev).set(transferId, request));
              addMessageToHistory(sender, {
                type: 'file_request',
                sender: sender,
                content: `Wants to send you a file:`,
                fileInfo: fileInfo,
                transferId: transferId,
              });
              break;
            }
            case ServerMessageType.FILE_ACCEPT_NOTICE: {
              const { recipient, fileInfo } = message;
              let transferId: string | null = null;
              sendingFiles.current.forEach((state, id) => {
                if (
                  state.recipient === recipient &&
                  state.fileInfo.name === fileInfo.name &&
                  state.status === 'pending_accept'
                ) {
                  transferId = id;
                }
              });
              if (transferId && sendingFiles.current.has(transferId)) {
                const sendingState = sendingFiles.current.get(transferId)!;
                if (sendingState.encryptedContent) {
                  sendingState.status = 'sending';
                  addMessageToHistory(recipient, {
                    type: 'file_notice',
                    content: `User accepted file: ${fileInfo.name}. Sending...`,
                    transferId,
                  });
                  sendChunk(transferId, sendingState);
                } else {
                  console.error(
                    `[ERROR] File content not found for accepted transfer ${transferId}. Cannot start sending.`
                  );
                  sendingFiles.current.delete(transferId);
                  addMessageToHistory(recipient, {
                    type: 'error',
                    content: `Error starting file transfer: Missing encrypted content.`,
                    transferId,
                  });
                }
              } else {
                console.warn(
                  `[WARN] Received file accept notice for unknown/stale transfer: ${fileInfo.name} from ${recipient}`
                );
              }
              break;
            }
            case ServerMessageType.FILE_REJECT_NOTICE: {
              const { recipient, fileInfo } = message;
              let transferId: string | null = null;
              sendingFiles.current.forEach((state, id) => {
                if (
                  state.recipient === recipient &&
                  state.fileInfo.name === fileInfo.name &&
                  state.status === 'pending_accept'
                ) {
                  transferId = id;
                }
              });
              if (transferId) {
                sendingFiles.current.delete(transferId);
                addMessageToHistory(recipient, {
                  type: 'file_notice',
                  content: `User rejected file: ${fileInfo.name}`,
                  transferId,
                });
                setTransferProgress((prev) => {
                  const next = { ...prev };
                  delete next[transferId!];
                  return next;
                });
              } else {
                console.warn(
                  `[WARN] Received file reject notice for unknown/stale transfer: ${fileInfo.name} from ${recipient}`
                );
              }
              break;
            }
            case ServerMessageType.FILE_CHUNK_RECEIVE: {
              const { sender, fileInfo, chunkData, chunkIndex, isLastChunk } = message;
              let transferId: string | null = null;
              receivingFiles.current.forEach((state, id) => {
                if (
                  state.sender === sender &&
                  state.fileInfo.name === fileInfo.name &&
                  state.status === 'receiving'
                ) {
                  transferId = id;
                }
              });
              if (!transferId || !receivingFiles.current.has(transferId)) {
                console.warn(
                  `[WARN] Received chunk for unknown/stale transfer from ${sender} for ${fileInfo.name}. Ignoring.`
                );
                return;
              }
              const receivingState = receivingFiles.current.get(transferId)!;
              if (!receivingState.aesKey) {
                console.error(
                  `[ERROR] Cannot process chunk for ${transferId}: AES key not available.`
                );
                receivingFiles.current.delete(transferId);
                addMessageToHistory(sender, {
                  type: 'error',
                  content: `File transfer error: Missing decryption key.`,
                  transferId,
                });
                return;
              }
              try {
                const chunkBuffer = base64ToBuffer(chunkData);
                receivingState.chunks.push(chunkBuffer);
                receivingState.receivedBytes += chunkBuffer.byteLength;
                const progress = Math.round(
                  (receivingState.receivedBytes / receivingState.fileInfo.size) * 100
                );
                setTransferProgress((prev) => ({ ...prev, [transferId!]: progress }));
                if (isLastChunk) {
                  receivingState.status = 'decrypting';
                  addMessageToHistory(sender, {
                    type: 'file_notice',
                    content: `File received: ${fileInfo.name}. Decrypting...`,
                    transferId,
                  });
                  const totalEncryptedBuffer = new Uint8Array(receivingState.receivedBytes);
                  let offset = 0;
                  for (const chunk of receivingState.chunks) {
                    totalEncryptedBuffer.set(new Uint8Array(chunk), offset);
                    offset += chunk.byteLength;
                  }
                  const decryptedFileBuffer = await decryptAesGcm(
                    receivingState.aesKey,
                    receivingState.fileInfo.iv,
                    bufferToBase64(totalEncryptedBuffer.buffer)
                  );
                  receivingState.status = 'complete';
                  const fileType = receivingState.fileInfo.type || 'application/octet-stream';
                  const blob = new Blob([decryptedFileBuffer], { type: fileType });
                  const objectUrl = URL.createObjectURL(blob);
                  if (fileType.startsWith('image/')) {
                    addMessageToHistory(sender, {
                      type: 'file_image',
                      sender: sender,
                      content: `Received image: ${fileInfo.name}`,
                      fileInfo: receivingState.fileInfo,
                      transferId: transferId,
                      objectUrl: objectUrl,
                    });
                  } else {
                    const a = document.createElement('a');
                    a.href = objectUrl;
                    a.download = receivingState.fileInfo.name;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(objectUrl);
                    addMessageToHistory(sender, {
                      type: 'file_notice',
                      content: `File downloaded: ${fileInfo.name}`,
                      transferId,
                    });
                  }
                  receivingFiles.current.delete(transferId);
                  setTransferProgress((prev) => {
                    const next = { ...prev };
                    delete next[transferId!];
                    return next;
                  });
                }
              } catch (error) {
                console.error(
                  `[ERROR] Error processing chunk or decrypting file ${transferId}:`,
                  error
                );
                receivingFiles.current.delete(transferId);
                addMessageToHistory(sender, {
                  type: 'error',
                  content: `File transfer failed: ${
                    error instanceof Error ? error.message : 'Unknown error'
                  }`,
                  transferId,
                });
                setTransferProgress((prev) => {
                  const next = { ...prev };
                  delete next[transferId!];
                  return next;
                });
              }
              break;
            } // End FILE_CHUNK_RECEIVE

            default:
              console.warn(
                '[WS] Unhandled message type received from server:',
                (message as any).type
              );
          }
        } catch (error) {
          console.error('[WS] Error processing received message:', error, 'Raw data:', event.data);
          addMessageToHistory(ALL_CHAT_KEY, {
            type: 'error',
            content: `[Client Error]: Failed to process message from server.`,
          });
        }
      }; // End onmessage
    }; // End connect

    // Initiate Connection
    if (connectTimeoutId.current) clearTimeout(connectTimeoutId.current);
    console.log('[WS] Scheduling initial connection attempt...');
    connectTimeoutId.current = setTimeout(() => {
      if (isEffectMounted) {
        connect();
      } else {
        console.log('[WS] Initial connection attempt skipped: effect unmounted.');
      }
    }, 10);

    // Effect Cleanup
    return () => {
      isEffectMounted = false;
      console.log('[WS] Connection useEffect cleanup running.');
      console.log('[Cleanup] Revoking potentially active Object URLs...');
      Object.values(chatHistories)
        .flat()
        .forEach((msg) => {
          if (msg.objectUrl) {
            URL.revokeObjectURL(msg.objectUrl);
          }
        });
      if (connectTimeoutId.current) {
        clearTimeout(connectTimeoutId.current);
        connectTimeoutId.current = null;
      }
      if (reconnectTimeoutId.current) {
        clearTimeout(reconnectTimeoutId.current);
        reconnectTimeoutId.current = null;
      }
      const socketToClean = localWsInstance;
      localWsInstance = null;
      if (ws.current === socketToClean) {
        ws.current = null;
      }
      if (socketToClean) {
        socketToClean.onopen = null;
        socketToClean.onclose = null;
        socketToClean.onerror = null;
        socketToClean.onmessage = null;
        if (
          socketToClean.readyState === WebSocket.OPEN ||
          socketToClean.readyState === WebSocket.CONNECTING
        ) {
          try {
            socketToClean.close(1000, 'Component unmounted');
          } catch (e) {
            console.warn('[WS] Error closing WebSocket during cleanup:', e);
          }
        }
      }
    };
  }, [addMessageToHistory]); // Dependency: only the stable callback

  // Effect for Sharing User's Public Key
  useEffect(() => {
    if (isLoggedIn && isConnected && myKeyPairState?.publicKey && !hasSharedKey.current) {
      const shareKey = async () => {
        if (!keyPairRef.current?.publicKey) {
          console.error('Failed to share public key: Key pair ref is missing!');
          return;
        }
        try {
          const exportedPublicKey = await exportPublicKey(keyPairRef.current.publicKey);
          sendData({ type: ClientMessageType.SHARE_PUBLIC_KEY, publicKey: exportedPublicKey });
          hasSharedKey.current = true;
        } catch (exportError) {
          console.error('Failed to export/share public key:', exportError);
          addMessageToHistory(ALL_CHAT_KEY, {
            type: 'error',
            content: '[Error]: Failed to share public key.',
          });
        }
      };
      shareKey();
    }
    if (!isLoggedIn || !isConnected) {
      hasSharedKey.current = false;
    }
  }, [isLoggedIn, isConnected, myKeyPairState]);

  // Event Handlers

  // Safely sends JSON data over the WebSocket connection.
  const sendData = (data: { type: ClientMessageType; [key: string]: unknown }) => {
    const socket = ws.current;
    const logType = data.type;
    if (socket?.readyState === WebSocket.OPEN) {
      try {
        const jsonData = JSON.stringify(data);
        let logDataPreview = jsonData;
        if (
          data.type === ClientMessageType.FILE_CHUNK ||
          data.type === ClientMessageType.SEND_MESSAGE
        ) {
          logDataPreview = `Payload Hidden`;
        } else if (data.type === ClientMessageType.SHARE_PUBLIC_KEY) {
          logDataPreview = `Public Key Hidden`;
        } else if (data.type === ClientMessageType.FILE_TRANSFER_REQUEST) {
          logDataPreview = `FileInfo Hidden`;
        }
        socket.send(jsonData);
      } catch (error) {
        console.error('[WS] Send failed:', error, 'Data attempted:', data);
        addMessageToHistory(ALL_CHAT_KEY, {
          type: 'error',
          content: '[Error]: Failed to send data to server.',
        });
      }
    } else {
      console.error(
        `[WS] Cannot send ${logType}: WebSocket not connected. State: ${socket?.readyState}`
      );
      addMessageToHistory(ALL_CHAT_KEY, {
        type: 'error',
        content: '[Error]: Cannot send message - not connected.',
      });
    }
  };

  // Handles login form submission.
  const handleLogin = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!isConnected) {
      setLoginError('Not connected to the server.');
      return;
    }
    if (!username || !password) {
      setLoginError('Username and password are required.');
      return;
    }
    if (!keyPairRef.current) {
      setLoginError('Cryptographic keys not ready. Please wait or refresh.');
      return;
    }
    setLoginError('');
    setSystemMessage('Logging in...');
    sendData({ type: ClientMessageType.LOGIN, username: username, password: password });
  };

  // Handles sending text messages (Encrypts for Server)
  const sendTextMessageContent = async (content: string) => {
    if (!isLoggedIn || !isConnected || !content.trim()) {
      console.warn('[sendTextMessageContent] Send skipped.');
      return;
    }
    if (!keyPairRef.current?.privateKey) {
      addMessageToHistory(currentChatKey, {
        type: 'error',
        content: 'Your keys are missing. Cannot send message.',
      });
      return;
    }

    // Check server key
    if (!serverPublicKey) {
      addMessageToHistory(currentChatKey, {
        type: 'error',
        content: 'Server key not available. Cannot send message yet.',
      });
      return;
    }

    const currentLoggedInUser = usernameRef.current;
    const trimmedContent = content.trim();

    try {
      // Generate ephemeral AES key
      const aesKey = await generateAesKey();
      // Encrypt message content with AES
      const { iv: ivBase64, ciphertext: ciphertextBase64 } = await encryptAesGcm(
        aesKey,
        new TextEncoder().encode(trimmedContent)
      );
      // Export AES key
      const aesKeyRaw = await exportAesKeyRaw(aesKey);
      // Encrypt AES key with SERVER's public key
      const encryptedAesKeyForServerB64 = await encryptRsaOaep(
        serverPublicKey,
        base64ToBuffer(aesKeyRaw)
      );
      // Prepare payload for server
      const payloadToServer = {
        iv: ivBase64,
        encryptedKey: encryptedAesKeyForServerB64,
        ciphertext: ciphertextBase64,
      };

      // Send message to server
      sendData({
        type: ClientMessageType.SEND_MESSAGE,
        recipient: selectedUser || undefined, // Send recipient if private, otherwise undefined for broadcast
        payload: payloadToServer,
      });

      // Add own message to history immediately
      addMessageToHistory(selectedUser || ALL_CHAT_KEY, {
        type: 'my_chat',
        content: trimmedContent,
        sender: currentLoggedInUser,
        isEncrypted: true, // Mark that it was encrypted for transit
      });
      setInputValue(''); // Clear input field
    } catch (error) {
      console.error('Error sending message:', error);
      addMessageToHistory(currentChatKey, {
        type: 'error',
        content: `[Send Error]: ${error instanceof Error ? error.message : 'Unknown error'}`,
      });
    }
  };

  // Handles form submission (Enter key press without Shift)
  const handleSendMessage = async (e?: React.FormEvent<HTMLFormElement>) => {
    e?.preventDefault();
    const trimmedInput = inputValue.trim();
    if (trimmedInput && !selectedFile) {
      await sendTextMessageContent(trimmedInput);
    } else if (selectedFile) {
      handleSendFile();
    }
  };
  // Handles key down events on the textarea
  const handleKeyDown = (event: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === 'Enter') {
      if (!event.shiftKey) {
        event.preventDefault();
        handleSendMessage();
      }
    }
  };
  // Handles logout process.
  const handleLogout = () => {
    if (!isLoggedIn) {
      return;
    }
    console.log('[App] Initiating logout...');
    const userToLogout = usernameRef.current;
    addMessageToHistory(ALL_CHAT_KEY, { type: 'system', content: '[Logging out...]' });
    if (ws.current?.readyState === WebSocket.OPEN) {
      sendData({ type: ClientMessageType.LOGOUT, username: userToLogout });
    }
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
    if (ws.current) {
      try {
        if (reconnectTimeoutId.current) {
          clearTimeout(reconnectTimeoutId.current);
          reconnectTimeoutId.current = null;
        }
        ws.current.close(1000, 'User logged out');
        console.log('[App] Logout: WebSocket close initiated.');
      } catch (e) {
        console.error('[App] Error closing WebSocket during logout:', e);
      }
      ws.current = null;
    }
  };
  // Handles username input change
  const handleUsernameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newUserInputValue = e.target.value;
    setUsername(newUserInputValue);
    usernameRef.current = newUserInputValue;
  };

  // Handles password input change
  const handlePasswordChange = (e: React.ChangeEvent<HTMLInputElement>) =>
    setPassword(e.target.value);

  // Handles text input change
  const handleInputChange = (e: React.ChangeEvent<HTMLTextAreaElement>) =>
    setInputValue(e.target.value);

  // Handles selecting a user from the list
  const handleUserSelect = (user: string) => {
    const currentLoggedInUser = usernameRef.current;
    if (user !== currentLoggedInUser) {
      setSelectedUser(user);
      if (isLoggedIn && !peerPublicKeys.has(user)) {
        addMessageToHistory(user, {
          type: 'system',
          content: `Requesting encryption key for ${user} (for file transfers)...`,
        });
        sendData({ type: ClientMessageType.REQUEST_PUBLIC_KEY, username: user });
      }
    }
  };

  // Handles selecting the main 'All Chat' view
  const handleSelectMainChat = () => setSelectedUser(null);

  // Handles file selection
  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      if (file.size > MAX_FILE_SIZE) {
        addMessageToHistory(currentChatKey, {
          type: 'error',
          content: `File is too large (Max: ${MAX_FILE_SIZE / 1024 / 1024}MB).`,
        });
        setSelectedFile(null);
      } else {
        setSelectedFile(file);
      }
      if (fileInputRef.current) fileInputRef.current.value = '';
    } else {
      setSelectedFile(null);
    }
  };

  // Initiates the file transfer process
  const handleSendFile = async () => {
    if (!selectedFile || !selectedUser || !isLoggedIn || !isConnected) {
      addMessageToHistory(currentChatKey, {
        type: 'error',
        content: 'Cannot send file. Ensure connected, logged in, user selected, file chosen.',
      });
      return;
    }
    if (!keyPairRef.current?.privateKey) {
      addMessageToHistory(selectedUser, {
        type: 'error',
        content: 'Your keys missing. Cannot initiate file transfer.',
      });
      return;
    }
    const recipientPublicKey = peerPublicKeys.get(selectedUser);
    if (!recipientPublicKey) {
      addMessageToHistory(selectedUser, {
        type: 'system',
        content: `Recipient's key needed for file transfer. Requesting... File not sent.`,
      });
      sendData({ type: ClientMessageType.REQUEST_PUBLIC_KEY, username: selectedUser });
      return;
    }
    const file = selectedFile;
    const transferId = generateUniqueId();
    addMessageToHistory(selectedUser, {
      type: 'file_notice',
      content: `Initiating file transfer: ${file.name}`,
      transferId,
    });
    setSelectedFile(null);
    try {
      const aesKey = await generateAesKey();
      const aesKeyRaw = await exportAesKeyRaw(aesKey);
      const encryptedAesKeyBase64 = await encryptRsaOaep(
        recipientPublicKey,
        base64ToBuffer(aesKeyRaw)
      );
      const fileBuffer = await file.arrayBuffer();
      const { iv: ivBase64, ciphertext: encryptedContentBase64 } = await encryptAesGcm(
        aesKey,
        fileBuffer
      );
      const encryptedContentBuffer = base64ToBuffer(encryptedContentBase64);
      const fileInfo: FileInfo = {
        name: file.name,
        size: file.size,
        type: file.type || 'application/octet-stream',
        iv: ivBase64,
        encryptedKey: encryptedAesKeyBase64,
      };
      const totalChunks = Math.ceil(encryptedContentBuffer.byteLength / CHUNK_SIZE);
      const sendingState: SendingFileState = {
        file: file,
        encryptedContent: encryptedContentBuffer,
        recipient: selectedUser,
        fileInfo: fileInfo,
        totalChunks: totalChunks,
        nextChunkIndex: 0,
        status: 'pending_accept',
      };
      sendingFiles.current.set(transferId, sendingState);
      setTransferProgress((prev) => ({ ...prev, [transferId]: 0 }));
      sendData({
        type: ClientMessageType.FILE_TRANSFER_REQUEST,
        recipient: selectedUser,
        fileInfo: fileInfo,
      });
    } catch (error) {
      console.error(`[ERROR] Failed to initiate file transfer ${transferId}:`, error);
      addMessageToHistory(selectedUser, {
        type: 'error',
        content: `Failed to start file transfer: ${
          error instanceof Error ? error.message : 'Unknown error'
        }`,
        transferId,
      });
      sendingFiles.current.delete(transferId);
      setTransferProgress((prev) => {
        const next = { ...prev };
        delete next[transferId];
        return next;
      });
    }
  };

  // Sends a single chunk of the file
  const sendChunk = (transferId: string, state: SendingFileState) => {
    if (!state.encryptedContent || state.status !== 'sending') {
      if (state.status !== 'complete' && state.status !== 'rejected') {
        sendingFiles.current.delete(transferId);
        setTransferProgress((prev) => {
          const next = { ...prev };
          delete next[transferId];
          return next;
        });
        addMessageToHistory(state.recipient, {
          type: 'error',
          content: `File transfer failed internally.`,
          transferId,
        });
      }
      return;
    }
    if (!ws.current || ws.current.readyState !== WebSocket.OPEN) {
      state.status = 'error';
      addMessageToHistory(state.recipient, {
        type: 'error',
        content: `File transfer failed: Connection lost.`,
        transferId,
      });
      setTransferProgress((prev) => ({ ...prev, [transferId]: -1 }));
      return;
    }
    const start = state.nextChunkIndex * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, state.encryptedContent.byteLength);
    const chunk = state.encryptedContent.slice(start, end);
    const isLastChunk = end >= state.encryptedContent.byteLength;
    sendData({
      type: ClientMessageType.FILE_CHUNK,
      recipient: state.recipient,
      fileInfo: { name: state.fileInfo.name },
      chunkData: bufferToBase64(chunk),
      chunkIndex: state.nextChunkIndex,
      isLastChunk: isLastChunk,
    });

    state.nextChunkIndex++;
    const progress = Math.round((state.nextChunkIndex / state.totalChunks) * 100);
    setTransferProgress((prev) => ({ ...prev, [transferId]: progress }));
    if (isLastChunk) {
      state.status = 'complete';
      addMessageToHistory(state.recipient, {
        type: 'file_notice',
        content: `File sent successfully: ${state.fileInfo.name}`,
        transferId,
      });
    } else {
      setTimeout(() => {
        if (
          sendingFiles.current.has(transferId) &&
          sendingFiles.current.get(transferId)?.status === 'sending'
        ) {
          sendChunk(transferId, state);
        }
      }, 10);
    }
  };
  // Handles accepting an incoming file transfer request
  const handleAcceptFile = async (transferId: string) => {
    const request = incomingFileRequests.get(transferId);
    if (!request) {
      return;
    }
    if (!keyPairRef.current?.privateKey) {
      addMessageToHistory(request.sender, {
        type: 'error',
        content: 'Cannot accept file: Your keys are missing.',
        transferId,
      });
      return;
    }
    const { sender, fileInfo } = request;
    try {
      const aesKeyBuffer = await decryptRsaOaep(
        keyPairRef.current.privateKey,
        fileInfo.encryptedKey
      );
      const aesKey = await importAesKeyRaw(bufferToBase64(aesKeyBuffer));
      const receivingState: ReceivingFileState = {
        id: transferId,
        sender: sender,
        fileInfo: fileInfo,
        aesKey: aesKey,
        chunks: [],
        receivedBytes: 0,
        status: 'receiving',
      };
      receivingFiles.current.set(transferId, receivingState);
      setTransferProgress((prev) => ({ ...prev, [transferId]: 0 }));
      setIncomingFileRequests((prev) => {
        const next = new Map(prev);
        next.delete(transferId);
        return next;
      });
      sendData({
        type: ClientMessageType.FILE_TRANSFER_ACCEPT,
        sender: sender,
        fileInfo: { name: fileInfo.name, size: fileInfo.size },
      });
      addMessageToHistory(sender, {
        type: 'file_notice',
        content: `Accepted file: ${fileInfo.name}. Receiving...`,
        transferId,
      });
    } catch (error) {
      console.error(`[ERROR] Failed to accept/prepare for file transfer ${transferId}:`, error);
      addMessageToHistory(sender, {
        type: 'error',
        content: `Failed to accept file transfer: ${
          error instanceof Error ? error.message : 'Decryption error'
        }`,
        transferId,
      });
      setIncomingFileRequests((prev) => {
        const next = new Map(prev);
        next.delete(transferId);
        return next;
      });
    }
  };
  // Handles rejecting an incoming file transfer request
  const handleRejectFile = (transferId: string) => {
    const request = incomingFileRequests.get(transferId);
    if (!request) {
      return;
    }
    const { sender, fileInfo } = request;
    setIncomingFileRequests((prev) => {
      const next = new Map(prev);
      next.delete(transferId);
      return next;
    });
    sendData({
      type: ClientMessageType.FILE_TRANSFER_REJECT,
      sender: sender,
      fileInfo: { name: fileInfo.name },
    });
    addMessageToHistory(sender, {
      type: 'file_notice',
      content: `Rejected file transfer: ${fileInfo.name}`,
      transferId,
    });
  };
  // Handles download button click
  const handleDownloadFile = (objectUrl: string | undefined, filename: string | undefined) => {
    if (!objectUrl || !filename) {
      return;
    }
    const a = document.createElement('a');
    a.href = objectUrl;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  // Handles inserting emojis
  const handleEmojiSelect = (emojiData: EmojiClickData) => {
    const emoji = emojiData.emoji;
    const input = messageInputRef.current;
    if (input) {
      const start = input.selectionStart ?? inputValue.length;
      const end = input.selectionEnd ?? inputValue.length;
      const newValue = inputValue.substring(0, start) + emoji + inputValue.substring(end);
      setInputValue(newValue);
      input.focus();
      setTimeout(() => {
        input.selectionStart = input.selectionEnd = start + emoji.length;
      }, 0);
    } else {
      setInputValue((prev) => prev + emoji);
    }
    setShowEmojiPicker(false);
  };

  // Derived State for UI rendering
  const currentMessages = chatHistories[currentChatKey] || [];
  const onlineUsersCount = users.filter((u) => u !== currentUsername).length;
  const fileTransferReady = selectedUser ? peerPublicKeys.has(selectedUser) : false;

  // Render UI
  return (
    <div className="flex flex-col h-screen bg-gradient-to-br from-blue-100 via-purple-100 to-pink-100 p-4 gap-4 font-sans">
      {/* Header */}
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
          {/* Indicate if server key is missing */}
          {isLoggedIn && !serverPublicKey && (
            <span className="text-orange-600 font-semibold">(Waiting for server key...)</span>
          )}
        </div>
      </header>

      {/* Main Layout */}
      <div className="flex flex-1 gap-4 overflow-hidden">
        {/* Sidebar */}
        <Card className="w-60 flex flex-col bg-white/80 backdrop-blur-sm border-gray-200 shadow-md rounded-lg">
          <CardHeader className="p-3 border-b bg-gray-50/80 rounded-t-lg">
            {' '}
            <CardTitle className="text-lg text-gray-700">Users ({users.length})</CardTitle>{' '}
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
                <Users className="h-5 w-5 text-gray-600" />{' '}
                <span className="font-medium">All Chat</span>
              </Button>
              <hr className="my-2 border-gray-200" />
              {/* User List */}
              <ul className="space-y-1">
                {users
                  .filter((u) => u !== currentUsername)
                  .map((user) => (
                    <li key={user}>
                      <Button
                        variant={selectedUser === user ? 'secondary' : 'ghost'}
                        className="w-full justify-start gap-2 text-sm h-9"
                        onClick={() => handleUserSelect(user)}
                        disabled={!isLoggedIn}
                        title={`Chat privately with ${user}`}
                      >
                        <User
                          className={`h-5 w-5 ${
                            selectedUser === user ? 'text-blue-700' : 'text-gray-500'
                          }`}
                        />
                        <span
                          className={`truncate font-medium ${
                            selectedUser === user ? 'text-blue-700' : 'text-gray-700'
                          }`}
                        >
                          {' '}
                          {user}{' '}
                        </span>
                        {/* Lock icon indicates readiness for end to end file transfers */}
                        {peerPublicKeys.has(user) ? (
                          <Lock
                            size={14}
                            className="ml-auto text-blue-500"
                            title="Ready for File Transfers"
                          />
                        ) : (
                          <Unlock
                            size={14}
                            className="ml-auto text-gray-400"
                            title="Key Missing for File Transfers"
                          />
                        )}
                      </Button>
                    </li>
                  ))}
                {isLoggedIn && onlineUsersCount === 0 && (
                  <li className="text-gray-500 italic text-center p-2 text-xs">
                    No other users online
                  </li>
                )}
                {!isLoggedIn && (
                  <li className="text-gray-500 italic text-center p-2 text-xs">
                    Log in to see users
                  </li>
                )}
              </ul>
            </ScrollArea>
          </CardContent>
        </Card>

        {/* Chat Area */}
        <Card className="flex-1 flex flex-col bg-white/80 backdrop-blur-sm border-gray-200 shadow-md rounded-lg overflow-hidden">
          {/* Chat Header */}
          <CardHeader className="p-3 border-b bg-gray-50/80 rounded-t-lg">
            <div className="flex justify-between items-center">
              <div className="flex items-center gap-2">
                <CardTitle className="text-lg text-gray-700">
                  {' '}
                  {selectedUser ? `Chat with ${selectedUser}` : 'All Chat'}{' '}
                </CardTitle>
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

          {/* Message Display */}
          <CardContent className="flex-1 p-0 overflow-hidden">
            <ScrollArea className="h-full w-full p-4">
              <div className="space-y-3">
                {currentMessages.map((msg, index) => {
                  const messageKey = msg.transferId
                    ? `${msg.transferId}-${msg.type}`
                    : msg.timestamp
                    ? `${msg.timestamp}-${index}`
                    : index;
                  // Render File Transfer Messages
                  if (msg.type === 'file_request' && msg.transferId && msg.fileInfo) {
                    const request = incomingFileRequests.get(msg.transferId);
                    if (!request) return null;
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
                    const progress = transferProgress[msg.transferId!] ?? null;
                    const isSending = sendingFiles.current.has(msg.transferId!);
                    const isReceiving = receivingFiles.current.has(msg.transferId!);
                    const statusText =
                      typeof msg.content === 'string' ? msg.content : 'File Notice';
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
                          {statusText}{' '}
                          {(isSending || isReceiving) &&
                            progress !== null &&
                            progress >= 0 &&
                            progress <= 100 && (
                              <Progress value={progress} className="w-full h-2 mt-1" />
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
                            alt={`Image received from ${msg.sender}: ${msg.fileInfo.name}`}
                            className="max-w-full h-auto rounded block object-contain bg-white"
                            onLoad={() => console.log(`Image ${msg.fileInfo?.name} loaded.`)}
                            onError={() =>
                              console.error(`Failed to load image ${msg.fileInfo?.name}`)
                            }
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

                  // Render Text Messages
                  if (msg.type === 'my_chat' || msg.type === 'chat') {
                    const contentString = typeof msg.content === 'string' ? msg.content : '';
                    let renderedContent: React.ReactNode = (
                      <div className="chat-content">{contentString}</div>
                    );
                    try {
                      const parsedHtml = marked.parse(contentString || '', { breaks: true });
                      const sanitizedHtml = DOMPurify.sanitize(parsedHtml);
                      renderedContent = (
                        <div
                          className="chat-content prose prose-sm max-w-none"
                          dangerouslySetInnerHTML={{ __html: sanitizedHtml || '' }}
                        />
                      );
                    } catch (e) {
                      console.error(`[Render ${messageKey}] Error parsing/sanitizing markdown:`, e);
                      renderedContent = (
                        <div className="chat-content whitespace-pre-wrap">{contentString}</div>
                      );
                    }

                    return (
                      <div
                        key={messageKey}
                        className={`flex flex-col ${
                          msg.type === 'my_chat' ? 'items-end' : 'items-start'
                        }`}
                      >
                        <div
                          className={`max-w-xs md:max-w-md lg:max-w-lg rounded-lg px-3 py-2 shadow-sm text-sm ${
                            msg.type === 'my_chat'
                              ? 'bg-blue-600 text-white'
                              : 'bg-gray-100 text-gray-900'
                          }`}
                        >
                          {msg.sender && msg.type !== 'my_chat' && (
                            <p className="text-xs font-semibold mb-0.5 text-gray-700">
                              {msg.sender}
                            </p>
                          )}
                          {renderedContent}
                        </div>
                      </div>
                    );
                  }

                  // System Messages and Errors
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
                        {typeof msg.content === 'string' ? msg.content : null}{' '}
                      </div>{' '}
                    </div>
                  );
                })}
                <div ref={messagesEndRef} />
              </div>
            </ScrollArea>
          </CardContent>

          {/* Input Area */}
          <CardFooter className="p-4 border-t bg-gray-50/80">
            {!isLoggedIn /* Login Form */ ? (
              <form onSubmit={handleLogin} className="w-full space-y-3">
                <h3 className="text-center font-medium text-gray-700">Please Log In</h3>
                {loginError && <p className="text-red-500 text-sm text-center">{loginError}</p>}
                {systemMessage && !loginError && (
                  <p className="text-yellow-600 text-sm text-center">{systemMessage}</p>
                )}
                <div className="flex flex-col sm:flex-row gap-2">
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
                  />
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
                  />
                </div>
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
                </Button>
              </form>
            ) : (
              /* Message Input Form Area */
              <div className="w-full flex items-end gap-2 relative">
                {/* File Attach Button  */}
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

                {/* Display Selected File Info OR Text Input */}
                {selectedFile && selectedUser /* File Selected View */ ? (
                  <div className="flex items-center gap-2 flex-1 bg-gray-100 p-1 rounded-md border h-10">
                    <FileIcon className="h-4 w-4 text-gray-600 shrink-0 ml-1" />
                    <span
                      className="text-sm text-gray-700 truncate flex-1"
                      title={selectedFile.name}
                    >
                      {' '}
                      {selectedFile.name} ({(selectedFile.size / 1024).toFixed(1)} KB){' '}
                    </span>
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
                    </Button>
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
                    </Button>
                  </div>
                ) : (
                  /* Standard Text Input View */
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
                      aria-label="Chat message input"
                      className="pr-10 flex-1 resize-none border rounded-md shadow-sm focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500 p-2 leading-tight text-sm"
                      minRows={1}
                      maxRows={5}
                      disabled={!isConnected || !serverPublicKey} // Disable if not connected OR server key not received yet
                      autoComplete="off"
                    />
                    {/* Emoji Picker */}
                    <Popover open={showEmojiPicker} onOpenChange={setShowEmojiPicker}>
                      <PopoverTrigger asChild>
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7 text-gray-500 hover:text-gray-700"
                          title="Select emoji"
                        >
                          {' '}
                          <Smile className="h-5 w-5" />{' '}
                        </Button>
                      </PopoverTrigger>
                      <PopoverContent className="w-auto p-0 mb-1" side="top" align="end">
                        {' '}
                        <EmojiPicker
                          onEmojiClick={handleEmojiSelect}
                          autoFocusSearch={false}
                          height={400}
                          lazyLoadEmojis={true}
                          theme={EmojiTheme.AUTO}
                        />{' '}
                      </PopoverContent>
                    </Popover>
                  </div>
                )}

                {/* Send Text Button */}
                {!selectedFile && (
                  <Button
                    type="button"
                    onClick={() => handleSendMessage()}
                    size="icon"
                    aria-label="Send message"
                    title={selectedUser ? 'Send Private Message' : 'Send Broadcast Message'}
                    disabled={!inputValue.trim() || !isConnected || !serverPublicKey} // Also disable if server key not ready
                    className="shrink-0"
                  >
                    {' '}
                    <SendHorizonal className="h-4 w-4" />{' '}
                  </Button>
                )}

                {/* Logout Button */}
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
            )}
          </CardFooter>
        </Card>
      </div>
    </div>
  );
}

export default App;
