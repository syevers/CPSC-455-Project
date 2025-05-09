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

## Setup and Guide Instructions

1. User can enter the website link:
    https://securechat.ct.ws/
2. User can login or sign up their Id and password
3.  In the chat room, all user can communication to everybody in the room, or they can click on username who they want to chat in private.
4. In the private chat room, User can send file to each other which is under <5MB> and in the format 'image/png', 'image/jpeg', 'application/pdf'.
- Sender will know when the Receiver accept and download the file by the loading line moving.
- The file will be stored on uploads/ folder in the Firebase Storage.
- Their chat log will be hash and stored on chatlogs/ folder of Firebase Database.
- Their credentials will be stored on users/ folder in the Firebase Database. 
5. If the user is not activing in 5 minutes, they will be disconnected and must be re-log in to continue.
6. User must wait awhile for typed wrong password many times.
