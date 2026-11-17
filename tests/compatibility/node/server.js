import http from 'node:http';
import { xxh32 } from '@node-rs/xxhash';

// This package calls a prebuilt native addon; install scripts remain disabled.
const hash = xxh32(Buffer.from('tailor'));
if (!Number.isInteger(hash) || hash === 0) throw new Error('native xxhash failed');

http.createServer((request, response) => {
  if (request.method !== 'GET' || request.url !== '/health') {
    response.writeHead(404).end();
    return;
  }
  response.writeHead(200, { 'content-type': 'application/json' });
  response.end(JSON.stringify({ status: 'ok', runtime: 'node', native: true, hash }));
}).listen(8080, '0.0.0.0');
