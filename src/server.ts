import { readFileSync } from 'fs';
import { WebSocketServer } from 'ws';
import https from 'https';

const PORT = 8080;

// https server options
const options = {
  key: readFileSync('../certs/private.pem'),
  cert: readFileSync('../certs/public.pem'),
};

const server = https.createServer(options).listen(PORT);
const wss = new WebSocketServer({
  server: server,
});

console.log(wss.address());

wss.on('connection', function connection(ws) {
  // console.log(wss.clients);
  console.log('connected.');
  ws.on('error', console.error);

  ws.on('message', function message(data) {
    console.log('received: %s', data);
  });

  ws.send('something');
});
