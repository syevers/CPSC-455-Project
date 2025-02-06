import { WebSocketServer } from 'ws';

const wss = new WebSocketServer({ port: 8080 });

console.log(wss.address());

wss.on('connection', function connection(ws) {
  console.log(wss.clients);
  console.log('connected.');
  ws.on('error', console.error);

  ws.on('message', function message(data) {
    console.log('received: %s', data);
  });

  ws.send('something');
});
