import React, { useCallback, useEffect, useRef, useState } from 'react';

// Shadcn UI Component Imports
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';

// Icons
import { LogOut, SendHorizonal, User } from 'lucide-react';

// Using wss:// - Requires manual browser trust for self-signed certs.
// Will change when development is done
const SERVER_URL = 'wss://127.0.0.1:8080';

// Define message types using an enum
enum MessageType {
  SYSTEM = 'system',
  CHAT = 'chat',
  MY_CHAT = 'my_chat',
  USER_LIST = 'userList',
  LOGIN = 'login',
  LOGOUT = 'logout',
  MESSAGE = 'message',
  PING = 'ping',
  PONG = 'pong',
}

// Interface for incoming WebSocket messages
interface ServerMessage {
  type: MessageType;
  content?: string;
  users?: string[];
}

// Interface for messages stored in the state for display
interface DisplayMessage {
  type: MessageType.SYSTEM | MessageType.CHAT | MessageType.MY_CHAT;
  content: string;
  sender?: string;
}

function App(): React.ReactElement {
  // State variables
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const [isLoggedIn, setIsLoggedIn] = useState<boolean>(false);
  const [username, setUsername] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [currentUsername, setCurrentUsername] = useState<string>('');
  const [messages, setMessages] = useState<DisplayMessage[]>([]);
  const [users, setUsers] = useState<string[]>([]);
  const [inputValue, setInputValue] = useState<string>('');
  const [loginError, setLoginError] = useState<string>('');
  const [systemMessage, setSystemMessage] = useState<string>('');
  // Refs
  const ws = useRef<WebSocket | null>(null);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);
  // Effects
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);
  const addMessage = useCallback(
    (type: DisplayMessage['type'], content: string, sender?: string) => {
      setMessages((prev) => [...prev, { type, content, sender }]);
    },
    []
  );
  useEffect(() => {
    const connect = () => {
      if (
        ws.current &&
        (ws.current.readyState === WebSocket.OPEN || ws.current.readyState === WebSocket.CONNECTING)
      ) {
        return;
      }
      console.log('[WebSocket] Attempting to connect to:', SERVER_URL);
      setSystemMessage('Connecting...');
      ws.current = new WebSocket(SERVER_URL);
      ws.current.onopen = () => {
        console.log('[WebSocket] Connected');
        setIsConnected(true);
        setSystemMessage('Connected. Please log in.');
        setLoginError('');
      };
      ws.current.onclose = (event: CloseEvent) => {
        console.log(`[WebSocket] Disconnected. Code: ${event.code}`);
        setIsConnected(false);
        setIsLoggedIn(false);
        setCurrentUsername('');
        setUsers([]);
        if (!event.wasClean) {
          setSystemMessage('Disconnected unexpectedly. Reconnecting...');
          setTimeout(connect, 5000);
        } else {
          setSystemMessage('Disconnected.');
        }
        ws.current = null;
      };
      ws.current.onerror = (event: Event) => {
        console.error('[WebSocket] Error:', event);
        setSystemMessage(
          'Connection error. If using wss:// with self-signed cert, ensure you have manually trusted it in your browser (visit https://127.0.0.1:8080).'
        );
        setLoginError('WebSocket connection failed.');
      };
      ws.current.onmessage = (event: MessageEvent) => {
        try {
          const message: ServerMessage = JSON.parse(event.data as string);
          switch (message.type) {
            case MessageType.SYSTEM:
              const content = message.content ?? '';
              addMessage(MessageType.SYSTEM, `[SERVER]: ${content}`);
              if (content === 'Login successful') {
                setIsLoggedIn(true);
                const loggedInUsername = username;
                setCurrentUsername(loggedInUsername);
                setLoginError('');
                setSystemMessage('');
                setUsername('');
                setPassword('');
              } else if (content.startsWith('Login failed')) {
                setLoginError(content);
                setIsLoggedIn(false);
                setCurrentUsername('');
              } else if (content.includes('Welcome')) {
                setSystemMessage(`[SERVER]: ${content}`);
              } else if (content.includes('blocked') || content.includes('too quickly')) {
                setSystemMessage(`[SERVER]: ${content}`);
              }
              break;
            case MessageType.CHAT:
              const chatMatch = message.content?.match(/^\[(.*?)\]:\s*(.*)$/);
              const sender = chatMatch ? chatMatch[1] : 'Unknown';
              const chatContent = chatMatch ? chatMatch[2] : message.content ?? '';
              addMessage(MessageType.CHAT, chatContent, sender);
              break;
            case MessageType.USER_LIST:
              setUsers(message.users ?? []);
              break;
            case MessageType.PING:
              if (ws.current?.readyState === WebSocket.OPEN) {
                ws.current.send(JSON.stringify({ type: MessageType.PONG }));
              }
              break;
            default:
              if (typeof event.data === 'string' && !event.data.startsWith('{')) {
                addMessage(MessageType.SYSTEM, `[RAW]: ${event.data}`);
              }
          }
        } catch (error) {
          console.error('[WebSocket] Parse error:', error);
          if (typeof event.data === 'string') {
            addMessage(MessageType.SYSTEM, `[RAW]: ${event.data}`);
          }
        }
      };
    };
    connect();
    return () => {
      if (ws.current) {
        console.log('[WebSocket] Cleanup: Closing.');
        ws.current.onclose = null;
        ws.current.onerror = null;
        ws.current.onmessage = null;
        ws.current.onopen = null;
        ws.current.close(1000, 'Component unmounting');
        ws.current = null;
      }
    };
  }, [addMessage]);

  // Event Handlers
  const sendData = (data: { type: MessageType; [key: string]: unknown }) => {
    if (ws.current?.readyState === WebSocket.OPEN) {
      try {
        ws.current.send(JSON.stringify(data));
      } catch (error) {
        console.error('Send fail:', error);
        addMessage(MessageType.SYSTEM, '[Send Error]');
      }
    } else {
      console.error('WS Not connected.');
      addMessage(MessageType.SYSTEM, '[Not Connected]');
    }
  };
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
    setLoginError('');
    setSystemMessage('Logging in...');
    sendData({ type: MessageType.LOGIN, username: username, password: password });
  };
  const handleSendMessage = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const trimmedInput = inputValue.trim();
    if (trimmedInput && isLoggedIn && isConnected) {
      if (trimmedInput.toLowerCase() === '/logout') {
        handleLogout();
      } else {
        sendData({ type: MessageType.MESSAGE, message: trimmedInput });
        addMessage(MessageType.MY_CHAT, trimmedInput, currentUsername);
        setInputValue('');
      }
    } else if (!isLoggedIn) {
      addMessage(MessageType.SYSTEM, '[Log in first]');
    } else if (!isConnected) {
      addMessage(MessageType.SYSTEM, '[Not connected]');
    }
  };
  const handleLogout = () => {
    if (isLoggedIn && isConnected && ws.current) {
      console.log('[App] Logging out...');
      addMessage(MessageType.SYSTEM, '[Logging out...]');
      sendData({ type: MessageType.LOGOUT, username: currentUsername });
      setIsLoggedIn(false);
      setCurrentUsername('');
      setUsers([]);
    }
  };
  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) =>
    setInputValue(e.target.value);
  const handleUsernameChange = (e: React.ChangeEvent<HTMLInputElement>) =>
    setUsername(e.target.value);
  const handlePasswordChange = (e: React.ChangeEvent<HTMLInputElement>) =>
    setPassword(e.target.value);

  // Render UI
  return (
    // Outermost container with gradient background
    <div className="flex flex-col h-screen bg-gradient-to-br from-red-200 via-blue-200 to-white p-4 gap-4">
      {/* Header */}
      <header className="text-center py-2">
        <h1 className="text-2xl font-bold text-gray-800">SecureChat</h1>
        <div className="text-sm text-gray-600">
          Status:{' '}
          {isConnected ? (
            <span className="text-green-600 font-semibold">Connected</span>
          ) : (
            <span className="text-red-600 font-semibold">Disconnected</span>
          )}
          {isLoggedIn && ` | User: ${currentUsername}`}
        </div>
      </header>

      {/* Sidebar + Chat Area */}
      <div className="flex flex-1 gap-4 overflow-hidden">
        {/* Sidebar */}
        <Card className="w-60 flex flex-col bg-white/70 backdrop-blur-sm border-blue-200">
          <CardHeader>
            <CardTitle className="text-lg">Users ({users.length})</CardTitle>
          </CardHeader>
          <CardContent className="flex-1 overflow-y-auto p-2">
            <ul className="space-y-2">
              {/* User list without avatars */}
              {users.map((user) => (
                <li
                  key={user}
                  className="flex items-center gap-2 p-1.5 rounded hover:bg-blue-100/50"
                >
                  <User
                    className={`h-5 w-5 ${
                      user === currentUsername ? 'text-blue-700' : 'text-gray-500'
                    }`}
                  />
                  <span
                    className={`truncate font-medium ${
                      user === currentUsername ? 'text-blue-700' : 'text-gray-700'
                    }`}
                  >
                    {user} {user === currentUsername ? '(You)' : ''}
                  </span>
                </li>
              ))}
              {users.length === 0 && (
                <li className="text-gray-500 italic text-center p-2">No users online</li>
              )}
            </ul>
          </CardContent>
        </Card>

        {/* Chat Area */}
        <Card className="flex-1 flex flex-col bg-white/70 backdrop-blur-sm border-blue-200 overflow-hidden">
          {/* Message Display */}
          <CardContent className="flex-1 p-0">
            <ScrollArea className="h-full w-full p-4">
              <div className="space-y-3">
                {/* System Messages */}
                {systemMessage && (
                  <div className="text-center text-xs text-gray-500 italic py-1">
                    {systemMessage}
                  </div>
                )}
                {/* Chat Messages */}
                {messages.map((msg, index) => (
                  <div
                    key={index}
                    className={`flex flex-col ${
                      msg.type === MessageType.MY_CHAT ? 'items-end' : 'items-start'
                    }`}
                  >
                    {/* Message Bubble */}
                    <div
                      className={`max-w-xs md:max-w-md lg:max-w-lg rounded-lg px-3 py-2 break-words ${
                        msg.type === MessageType.MY_CHAT
                          ? 'bg-blue-600 text-white' // Your messages
                          : msg.type === MessageType.CHAT
                          ? 'bg-gray-100 text-gray-900' // Others' messages
                          : 'text-center text-xs text-gray-500 italic w-full bg-transparent' // System messages
                      }`}
                    >
                      {/* Show sender name only for CHAT type */}
                      {msg.type === MessageType.CHAT && (
                        <p className="text-xs font-semibold mb-0.5">{msg.sender}</p>
                      )}
                      {msg.content}
                    </div>
                  </div>
                ))}
                {/* Scroll anchor */}
                <div ref={messagesEndRef} />
              </div>
            </ScrollArea>
          </CardContent>

          {/* Input Area */}
          <CardFooter className="p-4 border-t bg-gray-50/50">
            {!isLoggedIn ? (
              // Login Form
              <form onSubmit={handleLogin} className="w-full space-y-3">
                <h3 className="text-center font-medium text-gray-700">Please Log In</h3>
                {loginError && <p className="text-red-500 text-sm text-center">{loginError}</p>}
                <div className="flex gap-2">
                  <Input
                    type="text"
                    placeholder="Username"
                    value={username}
                    onChange={handleUsernameChange}
                    disabled={!isConnected}
                    aria-label="Username"
                    className="flex-1"
                  />
                  <Input
                    type="password"
                    placeholder="Password"
                    value={password}
                    onChange={handlePasswordChange}
                    disabled={!isConnected}
                    aria-label="Password"
                    className="flex-1"
                  />
                </div>
                <Button type="submit" disabled={!isConnected} className="w-full">
                  Login / Register
                </Button>
              </form>
            ) : (
              // Message Input Form
              <form onSubmit={handleSendMessage} className="w-full flex items-center gap-2">
                <Input
                  type="text"
                  placeholder="Type your message or /logout..."
                  value={inputValue}
                  onChange={handleInputChange}
                  aria-label="Chat message input"
                  className="flex-1"
                />
                <Button type="submit" size="icon" aria-label="Send message">
                  <SendHorizonal className="h-4 w-4" />
                </Button>
                <Button
                  type="button"
                  variant="destructive"
                  size="icon"
                  onClick={handleLogout}
                  aria-label="Logout"
                >
                  <LogOut className="h-4 w-4" />
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
