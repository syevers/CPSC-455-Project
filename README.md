# WebSocket Secure Chat Application

## Project Overview

This project implements a WebSocket-based secure chat application using TypeScript. It includes:

- A WebSocket server (`server.ts`) running over `wss://` (WebSocket Secure) with HTTPS.  
- A client application (`client.ts`) that connects to the WebSocket server for real-time messaging.
- 

## Features

- Secure WebSocket communication (`wss://`)  
- User authentication with username and password  
- Real-time messaging between connected clients  
- Active user tracking  
- Auto-reconnect on connection loss  
- `/logout` command for disconnecting  
- Heartbeat mechanism for connection health monitoring
-  **Secure file transfers** with encryption  
- **Emoji & rich media support** (basic text formatting for bold, italics, and links)  
- **Security hardening** with brute-force protection and robust logging  
- **End-to-End encryption** exploration (AES-256 for message content, RSA-4096 for key exchange)  
- **User authentication** with username and password creation, stored via hashed credentials  


## Prerequisites

Before running the project, ensure you have the following installed:

- Node.js (version 23+ recommended)  
- TypeScript (`npm install -g typescript`)  
- ts-node for running TypeScript files (`npm install -g ts-node`)  
- WebSocket package (`npm install ws`)  
- HTTPS support (`npm install https`)

## Setup Instructions

### 1. Install Dependencies

Navigate to the project directory and install the required Node modules:

```bash
npm install
```

### 2. Generate SSL Certificates
```bash
mkdir certs
openssl req -x509 -newkey rsa:2048 -keyout certs/private.pem -out certs/public.pem -days 365 -nodes
```

### 3. Start the WebSocket Server
Run the following command to start the server:
```bash
cd src
node server.ts
```
#### Expected output:
Expected output:
```
[SERVER] Listening on wss://0.0.0.0:8080
```
### 4. Connect a Client
Open a new terminal and start the client:
```BASH
node client.ts
```
#### Expected output:
```
Connecting to server...
[CONNECTED] Successfully connected to the server.
[SERVER]: Welcome to the WebSocket server!
[CONNECTED] Please enter your credentials:
Username:
```
Enter your username and password when prompted.

### 5. Send Messages
Once logged in, type a message and press Enter to send it.
To log out, type:
```
/logout
```

## Troubleshooting
### 1. Connection Refused (ECONNREFUSED)
 - Ensure the server is running (node src/server.ts).
 - Verify that port 8080 is open (netstat -an | find "8080").
 - If running on Windows, allow port 8080 through the firewall:
 - Open Windows Defender Firewall.
 - Go to Advanced settings > Inbound Rules > New Rule.
 - Select Port, choose TCP, and enter 8080.
 - Allow the connection and name the rule.

### 2. WebSocket SSL Issues (self-signed certificate error)
If the client fails due to a self-signed certificate, use the --no-check option with wscat:
```bash
wscat --no-check -c wss://127.0.0.1:8080
```

## Note: AI was used to help format this readme file
