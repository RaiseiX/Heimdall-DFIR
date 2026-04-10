const http = require("http"), fs = require("fs"), path = require("path");
const MIME = { ".html":"text/html",".js":"application/javascript",".css":"text/css",".json":"application/json",".png":"image/png",".jpg":"image/jpeg",".svg":"image/svg+xml",".ico":"image/x-icon",".woff":"font/woff",".woff2":"font/woff2" };
const DIR = path.join(__dirname, "dist");
http.createServer((req, res) => {
  let p = path.join(DIR, req.url === "/" ? "index.html" : req.url.split("?")[0]);
  if (!fs.existsSync(p) || fs.statSync(p).isDirectory()) p = path.join(DIR, "index.html");
  if (req.url.includes("/assets/")) res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
  fs.readFile(p, (err, data) => {
    if (err) { res.writeHead(404); res.end("Not found"); return; }
    res.writeHead(200, { "Content-Type": MIME[path.extname(p)] || "application/octet-stream" });
    res.end(data);
  });
}).listen(3000, () => console.log("Frontend serving on :3000"));
