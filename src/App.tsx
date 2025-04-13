import React, { useCallback, useEffect, useRef, useState } from 'react';

// Shadcn UI Component Imports
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';

// --- Icons ---
import { Lock, LogOut, MessageSquare, SendHorizonal, Unlock, User, Users, X } from 'lucide-react';

// --- Crypto Helper Functions ---
// Converts an ArrayBuffer to a Base64 string.
const bufferToBase64 = (buffer: ArrayBuffer): string => {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
};
// Converts a Base64 string to an ArrayBuffer.
const base64ToBuffer = (base64: string): ArrayBuffer => {
  const binary_string = atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
};
// Generates an RSA-OAEP 4096 key pair for encryption/decryption.
const generateRsaKeyPair = async (): Promise<CryptoKeyPair> => {
  console.log('Generating RSA-OAEP 4096 key pair...');
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
  console.log('RSA key pair generated.');
  return keyPair;
};
// Exports a public CryptoKey to Base64 encoded SPKI format.
const exportPublicKey = async (key: CryptoKey): Promise<string> => {
  const exportedSpki = await crypto.subtle.exportKey('spki', key);
  return bufferToBase64(exportedSpki);
};
// Imports a public key from Base64 encoded SPKI format.
const importPublicKey = async (base64Key: string): Promise<CryptoKey> => {
  const spkiBuffer = base64ToBuffer(base64Key);
  return await crypto.subtle.importKey(
    'spki',
    spkiBuffer,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['encrypt']
  );
};
// Generates a symmetric AES-GCM 256-bit key for content encryption.
const generateAesKey = async (): Promise<CryptoKey> => {
  return await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ]);
};
// Exports an AES CryptoKey to Base64 encoded raw format.
const exportAesKeyRaw = async (key: CryptoKey): Promise<string> => {
  const exportedRaw = await crypto.subtle.exportKey('raw', key);
  return bufferToBase64(exportedRaw);
};
// Imports an AES key from Base64 encoded raw format.
const importAesKeyRaw = async (base64Key: string): Promise<CryptoKey> => {
  const rawBuffer = base64ToBuffer(base64Key);
  return await crypto.subtle.importKey('raw', rawBuffer, { name: 'AES-GCM' }, true, [
    'encrypt',
    'decrypt',
  ]);
};
// Encrypts string data using AES-GCM. Returns IV and ciphertext as Base64 strings.
const encryptAesGcm = async (
  key: CryptoKey,
  data: string
): Promise<{ iv: string; ciphertext: string }> => {
  const encodedData = new TextEncoder().encode(data);
  const iv = crypto.getRandomValues(new Uint8Array(12)); // AES-GCM standard IV size
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, encodedData);
  return { iv: bufferToBase64(iv), ciphertext: bufferToBase64(ciphertext) };
};
// Decrypts AES-GCM ciphertext. Expects IV and ciphertext as Base64 strings.
const decryptAesGcm = async (
  key: CryptoKey,
  ivBase64: string,
  ciphertextBase64: string
): Promise<string> => {
  const iv = base64ToBuffer(ivBase64);
  const ciphertext = base64ToBuffer(ciphertextBase64);
  try {
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      ciphertext
    );
    return new TextDecoder().decode(decryptedBuffer);
  } catch (error) {
    console.error('AES-GCM Decryption failed:', error);
    return `[Decryption Error: Failed to decrypt message. Possible key mismatch or corrupted data.]`;
  }
};
// Encrypts an ArrayBuffer (e.g., an exported AES key) using an RSA-OAEP Public Key.
const encryptRsaOaep = async (publicKey: CryptoKey, data: ArrayBuffer): Promise<string> => {
  const encryptedBuffer = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, data);
  return bufferToBase64(encryptedBuffer);
};
// Decrypts Base64 encoded data using an RSA-OAEP Private Key. Returns ArrayBuffer.
const decryptRsaOaep = async (privateKey: CryptoKey, base64Data: string): Promise<ArrayBuffer> => {
  const encryptedBuffer = base64ToBuffer(base64Data);
  try {
    return await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, encryptedBuffer);
  } catch (error) {
    console.error('RSA-OAEP Decryption failed:', error);
    throw new Error('RSA Decryption Failed');
  }
};

// WebSocket Setup
const SERVER_URL = 'wss://127.0.0.1:8080';

// Message Types
// Client -> Server Message Types
enum ClientMessageType {
  LOGIN = 'login',
  LOGOUT = 'logout',
  PRIVATE_MESSAGE = 'private_message',
  MULTI_RECIPIENT_ENCRYPTED_MESSAGE = 'multi_recipient_encrypted_message',
  SHARE_PUBLIC_KEY = 'share_public_key',
  REQUEST_PUBLIC_KEY = 'request_public_key',
  PING = 'ping',
  PONG = 'pong',
}

// Server -> Client Message Types
enum ServerMessageType {
  SYSTEM = 'system',
  USER_LIST = 'userList',
  PRIVATE_MESSAGE_ECHO = 'private_message_echo',
  RECEIVE_ENCRYPTED_MESSAGE = 'receive_encrypted_message',
  RECEIVE_ENCRYPTED_BROADCAST_MESSAGE = 'receive_encrypted_broadcast_message',
  RECEIVE_PUBLIC_KEY = 'receive_public_key',
  PONG = 'pong',
  PING = 'ping',
}

// Client-Side Interfaces (refactor later)
// Interfaces for messages received FROM the server
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
interface EncryptedPayload {
  encryptedKey: string;
  iv: string;
  ciphertext: string;
}
interface ReceiveEncryptedMessage extends ServerMessageBase {
  type: ServerMessageType.RECEIVE_ENCRYPTED_MESSAGE;
  sender: string;
  payload: EncryptedPayload;
}
interface ReceiveEncryptedBroadcastMessage extends ServerMessageBase {
  type: ServerMessageType.RECEIVE_ENCRYPTED_BROADCAST_MESSAGE;
  sender: string;
  iv: string;
  ciphertext: string;
  encryptedKey: string;
}
interface PrivateMessageEcho extends ServerMessageBase {
  type: ServerMessageType.PRIVATE_MESSAGE_ECHO;
  recipient: string;
  payload: EncryptedPayload;
}
interface PingMessage extends ServerMessageBase {
  type: ServerMessageType.PING;
}
// Union type for all possible server messages
type ServerMessage =
  | SystemMessage
  | UserListMessage
  | ReceivePublicKeyMessage
  | ReceiveEncryptedMessage
  | ReceiveEncryptedBroadcastMessage
  | PrivateMessageEcho
  | PingMessage;

// UI State Interfaces
interface DisplayMessage {
  type: 'system' | 'chat' | 'my_chat' | 'encrypted' | 'decrypted' | 'error';
  content: string;
  sender?: string;
  recipient?: string;
  timestamp?: number;
  isEncrypted?: boolean;
}
interface ChatHistories {
  [peerUsernameOrAllChat: string]: DisplayMessage[];
}
const ALL_CHAT_KEY = 'All Chat';

// React Component
function App(): React.ReactElement {
  // State & Refs
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const [isLoggedIn, setIsLoggedIn] = useState<boolean>(false);
  const [username, setUsername] = useState<string>(''); // Input field state
  const [password, setPassword] = useState<string>(''); // Input field state
  const [currentUsername, setCurrentUsername] = useState<string>(''); // Actual logged-in user state
  const [chatHistories, setChatHistories] = useState<ChatHistories>({ [ALL_CHAT_KEY]: [] });
  const [users, setUsers] = useState<string[]>([]);
  const [inputValue, setInputValue] = useState<string>('');
  const [loginError, setLoginError] = useState<string>('');
  const [systemMessage, setSystemMessage] = useState<string>('');
  const [selectedUser, setSelectedUser] = useState<string | null>(null);
  const ws = useRef<WebSocket | null>(null);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);
  const isConnecting = useRef<boolean>(false);
  const usernameRef = useRef<string>(''); // Ref to hold username reliably *during* login process
  const isMounted = useRef<boolean>(true);
  const reconnectTimeoutId = useRef<NodeJS.Timeout | null>(null);
  const connectTimeoutId = useRef<NodeJS.Timeout | null>(null);
  const hasSharedKey = useRef<boolean>(false);
  const keyPairRef = useRef<CryptoKeyPair | null>(null);
  const [myKeyPairState, setMyKeyPairState] = useState<CryptoKeyPair | null>(null);
  const [peerPublicKeys, setPeerPublicKeys] = useState<Map<string, CryptoKey>>(new Map());

  // Effects
  // Determine current chat key
  const currentChatKey = selectedUser ?? ALL_CHAT_KEY;

  // Scroll effect
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [chatHistories, currentChatKey]);

  // Callback to add messages
  const addMessageToHistory = useCallback(
    (peerKey: string, message: Omit<DisplayMessage, 'timestamp'>) => {
      if (!isMounted.current) {
        console.warn('[addMessageToHistory] Attempted add while unmounted.');
        return;
      }
      const newMessage = { ...message, timestamp: Date.now() };
      setChatHistories((prev) => {
        const history = prev[peerKey] || [];
        if (
          history.length > 0 &&
          history[history.length - 1].content === newMessage.content &&
          history[history.length - 1].sender === newMessage.sender &&
          newMessage.type !== 'system' &&
          newMessage.type !== 'error'
        )
          return prev;
        return { ...prev, [peerKey]: [...history, newMessage] };
      });
    },
    []
  );

  // Effect to generate RSA key pair
  useEffect(() => {
    isMounted.current = true;
    console.log('RSA Key Gen Effect - Mounting');
    const setupCrypto = async () => {
      try {
        const keys = await generateRsaKeyPair();
        if (isMounted.current) {
          setMyKeyPairState(keys);
          keyPairRef.current = keys;
          console.log('RSA key pair generated and stored.');
        } else {
          console.log('RSA key pair generated BUT component unmounted before storing.');
        }
      } catch (error) {
        console.error('RSA key gen failed:', error);
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
        console.log('[WS] Connect skipped.');
        return;
      }
      if (reconnectTimeoutId.current) {
        clearTimeout(reconnectTimeoutId.current);
        reconnectTimeoutId.current = null;
      }
      console.log('[WS] Attempting connect...');
      isConnecting.current = true;
      if (isEffectMounted) {
        setSystemMessage('Connecting...');
        setLoginError('');
      } else {
        console.log('[WS] Connect aborted: unmounted.');
        isConnecting.current = false;
        return;
      }

      if (ws.current) {
        console.warn('[WS] ws.current not null before new. Cleaning up.');
        ws.current.close();
        ws.current = null;
      }

      const currentRunWs = new WebSocket(SERVER_URL);
      localWsInstance = currentRunWs;
      ws.current = currentRunWs;
      console.log('[WS] New WebSocket instance created.');

      currentRunWs.onopen = () => {
        if (ws.current !== currentRunWs || !isEffectMounted) {
          console.log('[WS] onopen ignored: stale/unmounted.');
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
        console.log(`[WS] WebSocket Disconnected (onclose). Code: ${event.code}`);
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
          setPeerPublicKeys(new Map()); // Clear state directly
          setSelectedUser(null);
          setSystemMessage('Disconnected. Reconnecting...');
          hasSharedKey.current = false;
          if (reconnectTimeoutId.current) clearTimeout(reconnectTimeoutId.current);
          reconnectTimeoutId.current = setTimeout(() => {
            if (isEffectMounted && !ws.current) {
              connect();
            } else {
              console.log('[WS] Reconnect skipped.');
            }
          }, 5000);
        } else {
          console.log('[WS] onclose skipped state updates/reconnect: unmounted.');
        }
      };

      currentRunWs.onerror = (event: Event) => {
        if (localWsInstance !== currentRunWs || !isEffectMounted) {
          console.log('[WS] onerror ignored: stale/unmounted.');
          return;
        }
        console.error('[WS] WebSocket Error:', event);
        isConnecting.current = false;
      };

      currentRunWs.onmessage = async (event: MessageEvent) => {
        if (ws.current !== currentRunWs || !isEffectMounted) {
          console.warn(`[WS] onmessage ignored: stale/unmounted. Data: ${event.data}`);
          return;
        }
        console.log('[DEBUG] WebSocket message received (raw):', event.data);
        try {
          const message = JSON.parse(event.data as string) as ServerMessage;
          console.log(`[DEBUG] WebSocket message parsed. Type: ${message.type}`);
          switch (message.type) {
            case ServerMessageType.SYSTEM:
              const content = message.content ?? '';
              console.log(`[DEBUG] Processing SYSTEM message: "${content}"`);
              if (content === 'Login successful!') {
                console.log('[DEBUG] Login successful. Updating state and ref...');
                // Read username from the ref which was updated by handleUsernameChange
                const loggedInUsername = usernameRef.current;
                if (!loggedInUsername) {
                  console.error('CRITICAL: usernameRef is empty during login success handling!');
                  setLoginError('Login failed: Internal error (ref empty).');
                  setIsLoggedIn(false);
                  setCurrentUsername('');
                  usernameRef.current = '';
                  break;
                }
                // Update state
                setCurrentUsername(loggedInUsername); // Set display state
                setIsLoggedIn(true);
                setLoginError('');
                setSystemMessage('');
                setUsername('');
                setPassword(''); // Clear inputs
                addMessageToHistory(ALL_CHAT_KEY, {
                  type: 'system',
                  content: `[SERVER]: ${content}`,
                });
                hasSharedKey.current = false; // Reset to trigger key sharing
                console.log(`[DEBUG] State/Ref updated for login: ${usernameRef.current}`);
              } else if (content.startsWith('Login failed')) {
                setLoginError(content);
                setIsLoggedIn(false);
                setCurrentUsername('');
                usernameRef.current = '';
              } else {
                addMessageToHistory(ALL_CHAT_KEY, {
                  type: 'system',
                  content: `[SERVER]: ${content}`,
                });
              }
              break;

            case ServerMessageType.USER_LIST:
              const newUsers = message.users ?? [];
              const loggedInUser = usernameRef.current; // Get logged-in user from REF
              console.log(
                `[DEBUG] Processing USER_LIST: ${newUsers}. Current logged in user (ref): '${loggedInUser}'`
              );
              setUsers(newUsers);

              if (selectedUser && !newUsers.includes(selectedUser)) {
                addMessageToHistory(selectedUser, {
                  type: 'system',
                  content: `User ${selectedUser} went offline.`,
                });
                setSelectedUser(null);
              }

              // Use functional update for peer keys to ensure atomicity
              setPeerPublicKeys((prevKeys) => {
                const updatedKeys = new Map(prevKeys);
                let changed = false;

                // Remove keys for users no longer online
                Array.from(updatedKeys.keys()).forEach((user) => {
                  if (!newUsers.includes(user)) {
                    updatedKeys.delete(user);
                    console.log(`[DEBUG] Removed stale public key for offline user: ${user}`);
                    changed = true;
                  }
                });

                // Request keys for new users (use ref for loggedInUser check)
                if (loggedInUser) {
                  newUsers.forEach((user) => {
                    if (user !== loggedInUser && !updatedKeys.has(user)) {
                      console.log(
                        `[DEBUG] User list update: Requesting missing public key for ${user}...`
                      );
                      sendData({ type: ClientMessageType.REQUEST_PUBLIC_KEY, username: user });
                      // No need to set 'changed' here, receiving key will update state
                    }
                  });
                } else {
                  console.log(
                    '[DEBUG] Skipping key requests in USER_LIST handler: Not logged in (ref is empty).'
                  );
                }

                // Return new map only if changed, otherwise return previous state
                return changed ? updatedKeys : prevKeys;
              });
              break;

            case ServerMessageType.RECEIVE_PUBLIC_KEY:
              console.log(`[DEBUG] Processing RECEIVE_PUBLIC_KEY for ${message.username}`);
              try {
                const importedKey = await importPublicKey(message.publicKey);
                // Use functional update for state
                setPeerPublicKeys((prev) => {
                  // Avoid unnecessary state update if key is already present and same
                  if (prev.has(message.username) && prev.get(message.username) === importedKey) {
                    return prev;
                  }
                  console.log(`[DEBUG] Stored public key for ${message.username}`);
                  return new Map(prev).set(message.username, importedKey);
                });
                if (selectedUser === message.username) {
                  addMessageToHistory(selectedUser, {
                    type: 'system',
                    content: `Encryption ready for ${selectedUser}.`,
                  });
                }
              } catch (importError) {
                console.error(`Failed import key for ${message.username}:`, importError);
                addMessageToHistory(message.username, {
                  type: 'error',
                  content: `Invalid key from ${message.username}.`,
                });
              }
              break;

            // Private
            case ServerMessageType.RECEIVE_ENCRYPTED_MESSAGE:
              console.log(`[DEBUG] Processing RECEIVE_ENCRYPTED_MESSAGE from ${message.sender}`);
              const privateSender = message.sender;
              const myPrivateKeyForPrivate = keyPairRef.current?.privateKey;
              if (!privateSender || !myPrivateKeyForPrivate) {
                console.warn(`Cannot decrypt private: Missing info`);
                addMessageToHistory(privateSender || 'Unknown', {
                  type: 'error',
                  content: `[Error receiving private: Missing info]`,
                });
                break;
              }
              try {
                const aesKeyBuffer = await decryptRsaOaep(
                  myPrivateKeyForPrivate,
                  message.payload.encryptedKey
                );
                const aesKey = await importAesKeyRaw(bufferToBase64(aesKeyBuffer));
                const decryptedContent = await decryptAesGcm(
                  aesKey,
                  message.payload.iv,
                  message.payload.ciphertext
                );
                console.log(`[DEBUG] Private decryption success from ${privateSender}.`);
                addMessageToHistory(privateSender, {
                  type: 'decrypted',
                  content: decryptedContent,
                  sender: privateSender,
                  isEncrypted: true,
                });
              } catch (decryptionError: any) {
                console.error(`Failed decrypt private from ${privateSender}:`, decryptionError);
                addMessageToHistory(privateSender, {
                  type: 'error',
                  content: `[Private Decrypt Fail from ${privateSender}]`,
                  sender: privateSender,
                });
              }
              break;

            case ServerMessageType.RECEIVE_ENCRYPTED_BROADCAST_MESSAGE:
              console.log(
                `[DEBUG] Processing RECEIVE_ENCRYPTED_BROADCAST_MESSAGE from ${message.sender}`
              );
              const broadcastSender = message.sender;
              const myPrivateKeyForBroadcast = keyPairRef.current?.privateKey;
              const currentLoggedInUserCheck = usernameRef.current;
              if (broadcastSender === currentLoggedInUserCheck) {
                console.log('[DEBUG] Ignored own broadcast.');
                break;
              }
              if (!broadcastSender || !myPrivateKeyForBroadcast) {
                console.warn(`Cannot decrypt broadcast: Missing info`);
                addMessageToHistory(ALL_CHAT_KEY, {
                  type: 'error',
                  content: `[Error receiving broadcast: Missing info]`,
                });
                break;
              }
              try {
                const aesKeyBuffer = await decryptRsaOaep(
                  myPrivateKeyForBroadcast,
                  message.encryptedKey
                );
                const aesKey = await importAesKeyRaw(bufferToBase64(aesKeyBuffer));
                const decryptedContent = await decryptAesGcm(
                  aesKey,
                  message.iv,
                  message.ciphertext
                );
                console.log(`[DEBUG] Broadcast decryption success from ${broadcastSender}.`);
                addMessageToHistory(ALL_CHAT_KEY, {
                  type: 'chat',
                  content: decryptedContent,
                  sender: broadcastSender,
                  isEncrypted: true,
                });
              } catch (decryptionError: any) {
                console.error(`Failed decrypt broadcast from ${broadcastSender}:`, decryptionError);
                addMessageToHistory(ALL_CHAT_KEY, {
                  type: 'error',
                  content: `[Broadcast Decrypt Fail from ${broadcastSender}]`,
                  sender: broadcastSender,
                });
              }
              break;

            case ServerMessageType.PING:
              console.log('[DEBUG] Received PING.');
              try {
                sendData({ type: ClientMessageType.PONG });
              } catch (e) {
                console.error('[ERROR] Failed PONG send:', e);
              }
              break;

            case ServerMessageType.PRIVATE_MESSAGE_ECHO:
              console.log(`[DEBUG] Received echo for private message to ${message.recipient}`);
              break;

            case ServerMessageType.PONG:
              console.log('[DEBUG] Received PONG (ignored).');
              break;
            default:
              console.warn('[WS] Unhandled message type:', (message as any).type);
          }
        } catch (error) {
          console.error('[WS] Error processing message:', error, event.data);
          addMessageToHistory(ALL_CHAT_KEY, {
            type: 'error',
            content: `[Msg Proc Error]: ${event.data}`,
          });
        }
      };
    };

    // Initiate Connection
    if (connectTimeoutId.current) clearTimeout(connectTimeoutId.current);
    console.log('[WS] Scheduling connection attempt...');
    connectTimeoutId.current = setTimeout(() => {
      if (isEffectMounted) {
        connect();
      } else {
        console.log('[WS] Connection skipped: unmounted.');
      }
    }, 10);

    // Effect Cleanup
    return () => {
      isEffectMounted = false;
      console.log('[WS] Connection useEffect cleanup running.');
      if (connectTimeoutId.current) {
        clearTimeout(connectTimeoutId.current);
        connectTimeoutId.current = null;
        console.log('[WS] Connect timeout cleared.');
      }
      if (reconnectTimeoutId.current) {
        clearTimeout(reconnectTimeoutId.current);
        reconnectTimeoutId.current = null;
        console.log('[WS] Reconnect timer cleared.');
      }
      const socketToClean = localWsInstance;
      localWsInstance = null;
      if (ws.current === socketToClean) {
        ws.current = null;
        console.log('[WS] ws.current nulled during cleanup.');
      } else {
        console.log('[WS] ws.current changed/nulled, skip nullification.');
      }
      if (socketToClean) {
        console.log(`[WS] Cleaning up WebSocket instance (State: ${socketToClean.readyState})`);
        socketToClean.onopen = null;
        socketToClean.onclose = null;
        socketToClean.onerror = null;
        socketToClean.onmessage = null;
        if (
          socketToClean.readyState === WebSocket.OPEN ||
          socketToClean.readyState === WebSocket.CONNECTING
        ) {
          try {
            socketToClean.close(1000, 'Component cleanup');
            console.log('[WS] Closing WebSocket from cleanup.');
          } catch (e) {
            console.warn('[WS] Error closing socket during cleanup:', e);
          }
        } else {
          console.log('[WS] WebSocket already closed/closing.');
        }
      } else {
        console.log('[WS] No local WebSocket instance for cleanup.');
      }
    };
  }, [addMessageToHistory]); // Dependency

  // Effect for Sharing Public Key
  useEffect(() => {
    if (isLoggedIn && isConnected && myKeyPairState?.publicKey && !hasSharedKey.current) {
      const shareKey = async () => {
        if (!keyPairRef.current?.publicKey) {
          console.error('Share key failed: ref missing!');
          return;
        }
        try {
          console.log('[DEBUG] Attempting to share public key...');
          const exportedPublicKey = await exportPublicKey(keyPairRef.current.publicKey);
          sendData({ type: ClientMessageType.SHARE_PUBLIC_KEY, publicKey: exportedPublicKey });
          hasSharedKey.current = true;
          console.log('[DEBUG] Public key shared.');
        } catch (exportError) {
          console.error('Failed export/share key:', exportError);
          addMessageToHistory(ALL_CHAT_KEY, { type: 'error', content: '[Failed share key]' });
        }
      };
      shareKey();
    }
    if (!isLoggedIn || !isConnected) {
      hasSharedKey.current = false;
    } // Reset on logout/disconnect
  }, [isLoggedIn, isConnected, myKeyPairState]);

  // Event Handlers

  // Safely sends JSON data over the WebSocket connection.
  const sendData = (data: { type: ClientMessageType; [key: string]: unknown }) => {
    const socket = ws.current;
    console.log(`[DEBUG] Attempting send ${data.type}. Socket state: ${socket?.readyState}`);
    if (socket?.readyState === WebSocket.OPEN) {
      try {
        const jsonData = JSON.stringify(data);
        let logDataPreview = jsonData;
        if (data.type === ClientMessageType.SHARE_PUBLIC_KEY)
          logDataPreview = `{"type":"${data.type}","publicKey":"<hidden>"}`;
        if (data.type === ClientMessageType.MULTI_RECIPIENT_ENCRYPTED_MESSAGE)
          logDataPreview = `{"type":"${data.type}","iv":"...","ciphertext":"...","encryptedKeys":{...}}`;
        if (data.type === ClientMessageType.PRIVATE_MESSAGE)
          logDataPreview = `{"type":"${data.type}","recipient":"${
            (data as any).recipient
          }","payload":{...}}`;
        console.log(`[DEBUG] Sending data: ${logDataPreview.substring(0, 250)}...`);
        socket.send(jsonData);
        if (data.type === ClientMessageType.PONG) console.log('[DEBUG] PONG sent.');
      } catch (error) {
        console.error('[WS] Send fail:', error, data);
        addMessageToHistory(ALL_CHAT_KEY, { type: 'error', content: '[Send Error]' });
      }
    } else {
      console.error(`[WS] Cannot send ${data.type}: Not connected. State: ${socket?.readyState}`);
      addMessageToHistory(ALL_CHAT_KEY, { type: 'error', content: '[Cannot send: Not connected]' });
    }
  };

  // Handles login form submission.
  const handleLogin = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!isConnected) {
      setLoginError('Not connected.');
      return;
    }
    if (!username || !password) {
      setLoginError('Inputs empty.');
      return;
    }
    if (!keyPairRef.current) {
      setLoginError('Keys not ready.');
      return;
    }
    setLoginError('');
    setSystemMessage('Logging in...');
    // usernameRef is updated by handleUsernameChange
    sendData({ type: ClientMessageType.LOGIN, username: username, password: password });
  };

  // Handles sending encrypted private or broadcast messages
  const handleSendMessage = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const trimmedInput = inputValue.trim();
    if (!trimmedInput || !isLoggedIn || !isConnected) return;
    if (trimmedInput.toLowerCase() === '/logout') {
      handleLogout();
      setInputValue('');
      return;
    }
    if (!keyPairRef.current?.privateKey || !keyPairRef.current?.publicKey) {
      addMessageToHistory(currentChatKey, { type: 'error', content: 'Your keys missing.' });
      return;
    }

    const currentLoggedInUser = usernameRef.current; // Use ref for sender identity

    try {
      if (selectedUser) {
        // Encrypted private messages
        const recipientPublicKey = peerPublicKeys.get(selectedUser);
        if (!recipientPublicKey) {
          addMessageToHistory(selectedUser, {
            type: 'system',
            content: `Requesting key for ${selectedUser}...`,
          });
          sendData({ type: ClientMessageType.REQUEST_PUBLIC_KEY, username: selectedUser });
          return;
        }
        console.log(`[DEBUG] Encrypting private for ${selectedUser}...`);
        const aesKey = await generateAesKey();
        const { iv: ivBase64, ciphertext: ciphertextBase64 } = await encryptAesGcm(
          aesKey,
          trimmedInput
        );
        const aesKeyRaw = await exportAesKeyRaw(aesKey);
        const encryptedAesKeyBase64 = await encryptRsaOaep(
          recipientPublicKey,
          base64ToBuffer(aesKeyRaw)
        );
        const payload: EncryptedPayload = {
          encryptedKey: encryptedAesKeyBase64,
          iv: ivBase64,
          ciphertext: ciphertextBase64,
        };
        sendData({
          type: ClientMessageType.PRIVATE_MESSAGE,
          recipient: selectedUser,
          payload: payload,
        });
        addMessageToHistory(selectedUser, {
          type: 'my_chat',
          content: trimmedInput,
          sender: currentLoggedInUser,
          isEncrypted: true,
        });
        console.log(`[DEBUG] Sent private to ${selectedUser}.`);
      } else {
        // Encrypted broadcast messages
        console.log('[DEBUG] Preparing encrypted broadcast...');
        const onlineUsers = users.filter((u) => u !== currentLoggedInUser);
        if (onlineUsers.length === 0) {
          addMessageToHistory(ALL_CHAT_KEY, { type: 'system', content: 'No others online.' });
          setInputValue('');
          return;
        }

        const aesKey = await generateAesKey();
        const { iv: ivBase64, ciphertext: ciphertextBase64 } = await encryptAesGcm(
          aesKey,
          trimmedInput
        );
        const aesKeyRaw = await exportAesKeyRaw(aesKey);
        const aesKeyBuffer = base64ToBuffer(aesKeyRaw);
        const encryptedKeysMap: { [recipientUsername: string]: string } = {};
        let recipientsWithKeys = 0;

        for (const recipient of onlineUsers) {
          const recipientPublicKey = peerPublicKeys.get(recipient);
          if (recipientPublicKey) {
            try {
              const encryptedAesKeyForRecipient = await encryptRsaOaep(
                recipientPublicKey,
                aesKeyBuffer
              );
              encryptedKeysMap[recipient] = encryptedAesKeyForRecipient;
              recipientsWithKeys++;
            } catch (keyEncryptError) {
              console.error(`Failed encrypt AES key for ${recipient}:`, keyEncryptError);
            }
          } else {
            console.warn(`[DEBUG] No public key for broadcast recipient ${recipient}. Skipping.`);
          }
        }

        if (recipientsWithKeys > 0) {
          sendData({
            type: ClientMessageType.MULTI_RECIPIENT_ENCRYPTED_MESSAGE,
            iv: ivBase64,
            ciphertext: ciphertextBase64,
            encryptedKeys: encryptedKeysMap,
          });
          console.log(`[DEBUG] Sent broadcast for ${recipientsWithKeys} recipients.`);
          addMessageToHistory(ALL_CHAT_KEY, {
            type: 'my_chat',
            content: trimmedInput,
            sender: currentLoggedInUser,
            isEncrypted: true,
          });
        } else {
          addMessageToHistory(ALL_CHAT_KEY, {
            type: 'error',
            content: 'Could not encrypt broadcast for any online users (missing keys?).',
          });
        }
      }
      setInputValue(''); // Clear input on success/attempt
    } catch (error) {
      console.error('Error sending message:', error);
      addMessageToHistory(currentChatKey, {
        type: 'error',
        content: `[Send Fail: ${error instanceof Error ? error.message : 'Unknown'}]`,
      });
    }
  };

  // Handles logout process.
  const handleLogout = () => {
    if (!isLoggedIn) {
      console.warn('Logout called when not logged in.');
      return;
    }
    console.log('[App] Initiating logout...');
    // Get username from ref before clearing
    const userToLogout = usernameRef.current;
    addMessageToHistory(ALL_CHAT_KEY, { type: 'system', content: '[Logging out...]' });
    if (ws.current?.readyState === WebSocket.OPEN) {
      sendData({ type: ClientMessageType.LOGOUT, username: userToLogout });
    }
    // Clear state and ref immediately
    setIsLoggedIn(false);
    setCurrentUsername('');
    usernameRef.current = '';
    setUsers([]);
    setSelectedUser(null);
    setInputValue('');
    setPeerPublicKeys(new Map());
    hasSharedKey.current = false;
    setIsConnected(false);
    setSystemMessage('Logged out.');
    if (ws.current) {
      try {
        ws.current.close(1000, 'Logout');
        console.log('[App] Logout: WS close initiated.');
      } catch (e) {
        console.error('[App] Error closing WS during logout:', e);
      }
      ws.current = null;
    }
    if (reconnectTimeoutId.current) {
      clearTimeout(reconnectTimeoutId.current);
      reconnectTimeoutId.current = null;
    }
  };

  // Input Change Handlers
  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) =>
    setInputValue(e.target.value);
  // Update state and ref on input change
  const handleUsernameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newUserInputValue = e.target.value;
    setUsername(newUserInputValue); // Update input state
    usernameRef.current = newUserInputValue; // Update ref immediately
  };
  const handlePasswordChange = (e: React.ChangeEvent<HTMLInputElement>) =>
    setPassword(e.target.value);

  // User Selection Handler
  const handleUserSelect = (user: string) => {
    const currentLoggedInUser = usernameRef.current; // Use ref
    if (user !== currentLoggedInUser) {
      setSelectedUser(user);
      if (isLoggedIn && !peerPublicKeys.has(user)) {
        // *** Use State ***
        addMessageToHistory(user, { type: 'system', content: `Requesting key for ${user}...` });
        sendData({ type: ClientMessageType.REQUEST_PUBLIC_KEY, username: user });
      }
    }
  };
  const handleSelectMainChat = () => setSelectedUser(null);

  // Derived State for UI rendering (using state for UI dependencies)
  const currentMessages = chatHistories[currentChatKey] || [];
  const onlineUsersCount = users.filter((u) => u !== currentUsername).length;
  // Use State for counts/readiness checks
  const availableKeysCount = Array.from(peerPublicKeys.keys()).filter(
    (u) => u !== currentUsername && users.includes(u)
  ).length;
  const broadcastReady =
    isLoggedIn && onlineUsersCount > 0 && availableKeysCount === onlineUsersCount;
  const privateReady = selectedUser ? peerPublicKeys.has(selectedUser) : false;

  // Render UI
  return (
    <div className="flex flex-col h-screen bg-gradient-to-br from-blue-100 via-purple-100 to-pink-100 p-4 gap-4 font-sans">
      {/* Header */}
      <header className="text-center py-2">
        <h1 className="text-2xl font-bold text-gray-800">Secure Chat</h1>
        <div className="text-sm text-gray-600 mt-1">
          Status:{' '}
          {isConnected ? (
            <span className="text-green-600 font-semibold">Connected</span>
          ) : (
            <span className="text-red-600 font-semibold">Disconnected</span>
          )}
          {isLoggedIn && currentUsername && ` | User: ${currentUsername}`}
          {systemMessage && <span className="ml-2 text-gray-500 italic">({systemMessage})</span>}
          {!keyPairRef.current && !isLoggedIn && (
            <span className="ml-2 text-orange-600 font-semibold">(Generating keys...)</span>
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
              >
                <Users className="h-5 w-5 text-gray-600" />{' '}
                <span className="font-medium">All Chat</span>
                {/* Broadcast Lock/Unlock: Use derived state */}
                {isLoggedIn && onlineUsersCount > 0 ? (
                  broadcastReady ? (
                    <Lock size={14} className="ml-auto text-green-600" title="Broadcast Ready" />
                  ) : (
                    <Unlock
                      size={14}
                      className="ml-auto text-orange-500"
                      title={`Broadcast Not Ready (${availableKeysCount}/${onlineUsersCount} Keys)`}
                    />
                  )
                ) : (
                  <span className="ml-auto w-3.5 h-3.5"></span>
                )}
              </Button>
              <hr className="my-2 border-gray-200" />
              {/* User List */}
              <ul className="space-y-1">
                {/* Use state for user list rendering */}
                {users
                  .filter((u) => u !== currentUsername)
                  .map((user) => (
                    <li key={user}>
                      <Button
                        variant={selectedUser === user ? 'secondary' : 'ghost'}
                        className="w-full justify-start gap-2 text-sm h-9"
                        onClick={() => handleUserSelect(user)}
                        disabled={!isLoggedIn}
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
                          {user}
                        </span>
                        {/* Private Lock/Unlock: Use state */}
                        {peerPublicKeys.has(user) ? (
                          <Lock
                            size={14}
                            className="ml-auto text-green-600"
                            title="Encryption Ready (Private)"
                          />
                        ) : (
                          <Unlock
                            size={14}
                            className="ml-auto text-orange-500"
                            title="Key Missing (Private)"
                          />
                        )}
                      </Button>
                    </li>
                  ))}
                {isLoggedIn && onlineUsersCount === 0 && (
                  <li className="text-gray-500 italic text-center p-2 text-xs">No others online</li>
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
                  {selectedUser ? `Chat with ${selectedUser}` : 'All Chat'}
                </CardTitle>
                {/* Encryption Status Indicator: Use derived state */}
                {selectedUser ? (
                  privateReady ? (
                    <Lock size={16} className="text-green-600" title="Private Chat" />
                  ) : (
                    <Unlock size={16} className="text-orange-500" title="Waiting for key..." />
                  )
                ) : onlineUsersCount > 0 ? (
                  broadcastReady ? (
                    <Lock size={16} className="text-green-600" title="Broadcast" />
                  ) : (
                    <Unlock
                      size={16}
                      className="text-orange-500"
                      title="Broadcast Not Fully Encrypted"
                    />
                  )
                ) : null}
              </div>
              {selectedUser && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={handleSelectMainChat}
                  className="text-xs text-blue-600 hover:text-blue-800"
                  title="Back to All Chat"
                >
                  <X className="h-4 w-4 mr-1" /> Back to All
                </Button>
              )}
            </div>
          </CardHeader>

          {/* Message Display */}
          <CardContent className="flex-1 p-0 overflow-hidden">
            <ScrollArea className="h-full w-full p-4">
              <div className="space-y-3">
                {currentMessages.map((msg, index) => (
                  <div
                    key={msg.timestamp ? `${msg.timestamp}-${index}` : index}
                    className={`flex flex-col ${
                      msg.type === 'my_chat' ? 'items-end' : 'items-start'
                    }`}
                  >
                    <div
                      className={`max-w-xs md:max-w-md lg:max-w-lg rounded-lg px-3 py-2 break-words shadow-sm text-sm ${
                        msg.type === 'my_chat'
                          ? 'bg-blue-600 text-white'
                          : msg.type === 'chat' || msg.type === 'decrypted'
                          ? 'bg-gray-100 text-gray-900'
                          : msg.type === 'error'
                          ? 'bg-red-100 text-red-700 text-xs italic w-full shadow-none text-center'
                          : 'text-center text-xs text-gray-500 italic w-full bg-transparent shadow-none'
                      }`}
                    >
                      {(msg.type === 'chat' || msg.type === 'decrypted') && msg.sender && (
                        <p className="text-xs font-semibold mb-0.5 text-gray-700">{msg.sender}</p>
                      )}
                      {msg.isEncrypted && (
                        <Lock
                          size={12}
                          className="inline-block mr-1 mb-0.5 text-gray-400"
                          title="Encrypted"
                        />
                      )}
                      {msg.content}
                    </div>
                  </div>
                ))}
                <div ref={messagesEndRef} />
              </div>
            </ScrollArea>
          </CardContent>

          {/* Input Area */}
          <CardFooter className="p-4 border-t bg-gray-50/80 rounded-b-lg">
            {!isLoggedIn /* Login Form */ ? (
              <form onSubmit={handleLogin} className="w-full space-y-3">
                <h3 className="text-center font-medium text-gray-700">Please Log In</h3>
                {loginError && !systemMessage && (
                  <p className="text-red-500 text-sm text-center">{loginError}</p>
                )}
                {systemMessage && !loginError && (
                  <p className="text-yellow-600 text-sm text-center">{systemMessage}</p>
                )}
                <div className="flex gap-2">
                  <Input
                    type="text"
                    placeholder="Username"
                    value={username}
                    onChange={handleUsernameChange}
                    disabled={!isConnected || !keyPairRef.current}
                    aria-label="Username"
                    className="flex-1"
                    autoComplete="username"
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
                  />
                </div>
                <Button
                  type="submit"
                  disabled={!isConnected || !keyPairRef.current}
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
              /* Message Form */
              <form onSubmit={handleSendMessage} className="w-full flex items-center gap-2">
                <Input
                  type="text"
                  placeholder={
                    selectedUser
                      ? privateReady
                        ? `Send message to ${selectedUser}...`
                        : `Waiting for ${selectedUser}'s key...`
                      : onlineUsersCount > 0
                      ? broadcastReady
                        ? `Send broadcast...`
                        : `Send broadcast (${availableKeysCount}/${onlineUsersCount} encryption keys)...`
                      : `Send broadcast (no users online)...`
                  }
                  value={inputValue}
                  onChange={handleInputChange}
                  aria-label="Chat message input"
                  className="flex-1"
                  disabled={!isConnected || (!!selectedUser && !privateReady)}
                  autoComplete="off"
                />
                <Button
                  type="submit"
                  size="icon"
                  aria-label="Send message"
                  title={
                    selectedUser
                      ? 'Send Encrypted Private Message'
                      : 'Send Encrypted Broadcast Message'
                  }
                  disabled={
                    !inputValue.trim() ||
                    !isConnected ||
                    (!!selectedUser && !privateReady) ||
                    (!selectedUser && onlineUsersCount === 0)
                  }
                >
                  {' '}
                  <Lock size={16} />{' '}
                </Button>
                <Button
                  type="button"
                  variant="destructive"
                  size="icon"
                  onClick={handleLogout}
                  aria-label="Logout"
                  title="Logout"
                  disabled={!isConnected}
                >
                  {' '}
                  <LogOut className="h-4 w-4" />{' '}
                </Button>
              </form>
            )}
          </CardFooter>
        </Card>
      </div>
    </div>
  );
}

export default App;
