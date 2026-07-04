const http = require("http");
const fs = require("fs");
const path = require("path");

const port = process.env.PORT || 3000;

const server = http.createServer((req, res) => {
  const url = req.url.split("?")[0];

  if (url === "/" || url === "/protected") {
    return serveFile(res, "public/protected.html", "text/html");
  }

  if (url === "/widget.html") {
    return serveFile(res, "public/widget.html", "text/html");
  }

  if (url === "/widget-callback.html") {
    return serveFile(res, "public/widget-callback.html", "text/html");
  }

  if (url.startsWith("/public/")) {
    return serveFile(res, url.substring(1), getContentType(url));
  }

  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not found");
});

function serveFile(res, relativePath, contentType) {
  const filePath = path.join(__dirname, relativePath);

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("File not found");
      return;
    }

    res.writeHead(200, { "Content-Type": contentType });
    res.end(data);
  });
}

function getContentType(url) {
  if (url.endsWith(".html")) return "text/html";
  if (url.endsWith(".js")) return "text/javascript";
  if (url.endsWith(".css")) return "text/css";
  if (url.endsWith(".json")) return "application/json";
  return "text/plain";
}

server.listen(port, () => {
  console.log(`Auth0 backend widget lab running on http://localhost:${port}`);
});
