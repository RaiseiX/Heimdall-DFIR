const http = require("http"), fs = require("fs"), path = require("path");
const MIME = { ".html":"text/html",".js":"application/javascript",".css":"text/css",".json":"application/json",".png":"image/png",".jpg":"image/jpeg",".svg":"image/svg+xml",".ico":"image/x-icon",".woff":"font/woff",".woff2":"font/woff2" };
const DIR = path.join(__dirname, "dist");

function cacheControlFor(url) {
  return String(url || "").includes("/assets/")
    ? "public, max-age=31536000, immutable"
    : "no-cache, must-revalidate";
}

const server = http.createServer((req, res) => {
  let p = path.join(DIR, req.url === "/" ? "index.html" : req.url.split("?")[0]);
  if (!fs.existsSync(p) || fs.statSync(p).isDirectory()) p = path.join(DIR, "index.html");
  fs.readFile(p, (err, data) => {
    if (err) { res.writeHead(404); res.end("Not found"); return; }
    res.writeHead(200, {
      "Content-Type": MIME[path.extname(p)] || "application/octet-stream",
      "Cache-Control": cacheControlFor(req.url),
    });
    res.end(data);
  });
});

if (require.main === module) {
  server.listen(3000, () => console.log("Frontend serving on :3000"));
}

module.exports = { server, cacheControlFor };
