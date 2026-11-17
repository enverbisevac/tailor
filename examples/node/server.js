import http from "node:http";

const port = Number.parseInt(process.env.PORT ?? "8080", 10);
const server = http.createServer((request, response) => {
  if (request.method !== "GET" || request.url !== "/health") {
    response.writeHead(404, { "content-type": "application/json" });
    response.end('{"error":"not found"}\n');
    return;
  }

  response.writeHead(200, { "content-type": "application/json" });
  response.end('{"runtime":"node","status":"ok"}\n');
});

server.requestTimeout = 5_000;
server.headersTimeout = 6_000;
server.listen(port, "0.0.0.0", () => {
  console.log(`Node health service listening on :${port}`);
});
