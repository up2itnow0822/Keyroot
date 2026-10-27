import { createServer } from 'node:http';

// The skeleton deliberately exposes no mutation route. U10 owns the authenticated API.
const server = createServer((req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  if (req.method === 'GET' && req.url === '/api/health') {
    res.end(JSON.stringify({ service: 'keyroot', mode: 'demo', mutation: 'disabled' }));
  } else {
    res.writeHead(404).end(JSON.stringify({ error: 'not_found' }));
  }
});
server.listen(9047, '127.0.0.1');
for (const signal of ['SIGINT', 'SIGTERM'] as const) process.on(signal, () => server.close());
