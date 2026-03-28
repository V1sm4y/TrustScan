const http = require("http");
const fs = require("fs");
const path = require("path");
const { URL } = require("url");

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, "public");

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(payload));
}

function sendFile(res, filePath, contentType) {
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Not found");
      return;
    }

    res.writeHead(200, { "Content-Type": contentType });
    res.end(data);
  });
}

function normalizeInputUrl(input) {
  if (!input || typeof input !== "string") {
    throw new Error("Please enter a URL.");
  }

  const trimmed = input.trim();
  const withProtocol = /^[a-zA-Z][a-zA-Z\d+\-.]*:/.test(trimmed) ? trimmed : `https://${trimmed}`;
  const parsed = new URL(withProtocol);

  if (!parsed.hostname) {
    throw new Error("Could not read a hostname from that URL.");
  }

  return parsed;
}

function getRiskLevel(isHttps, domainAgeDays) {
  if (!isHttps) {
    return "High risk";
  }

  if (domainAgeDays == null) {
    return "Medium risk";
  }

  if (domainAgeDays < 30) {
    return "High risk";
  }

  if (domainAgeDays < 180) {
    return "Medium risk";
  }

  return "Low risk";
}

function parseDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function extractCreationDateFromRdap(payload) {
  if (!payload || typeof payload !== "object") {
    return null;
  }

  if (payload.events && Array.isArray(payload.events)) {
    const createdEvent = payload.events.find((event) => {
      const action = String(event.eventAction || "").toLowerCase();
      return action === "registration" || action === "registered";
    });

    if (createdEvent && createdEvent.eventDate) {
      return parseDate(createdEvent.eventDate);
    }
  }

  if (payload.creationDate) {
    return parseDate(payload.creationDate);
  }

  return null;
}

async function fetchDomainAgeDays(hostname) {
  const rdapUrl = `https://rdap.org/domain/${encodeURIComponent(hostname)}`;
  const response = await fetch(rdapUrl, {
    headers: {
      Accept: "application/rdap+json, application/json"
    }
  });

  if (!response.ok) {
    throw new Error(`RDAP lookup failed with status ${response.status}.`);
  }

  const payload = await response.json();
  const createdAt = extractCreationDateFromRdap(payload);

  if (!createdAt) {
    return null;
  }

  const ageMs = Date.now() - createdAt.getTime();
  return Math.max(0, Math.floor(ageMs / 86400000));
}

async function analyzeUrl(input) {
  const parsedUrl = normalizeInputUrl(input);
  const isHttps = parsedUrl.protocol === "https:";

  let domainAgeDays = null;
  let domainAgeError = null;

  try {
    domainAgeDays = await fetchDomainAgeDays(parsedUrl.hostname);
  } catch (error) {
    domainAgeError = error.message;
  }

  return {
    normalizedUrl: parsedUrl.toString(),
    isHttps,
    domain: parsedUrl.hostname,
    domainAgeDays,
    risk: getRiskLevel(isHttps, domainAgeDays),
    domainAgeError
  };
}

const server = http.createServer(async (req, res) => {
  const parsedRequestUrl = new URL(req.url, `http://${req.headers.host}`);

  if (req.method === "GET" && parsedRequestUrl.pathname === "/") {
    sendFile(res, path.join(PUBLIC_DIR, "index.html"), "text/html; charset=utf-8");
    return;
  }

  if (req.method === "GET" && parsedRequestUrl.pathname === "/styles.css") {
    sendFile(res, path.join(PUBLIC_DIR, "styles.css"), "text/css; charset=utf-8");
    return;
  }

  if (req.method === "POST" && parsedRequestUrl.pathname === "/api/analyze") {
    let body = "";

    req.on("data", (chunk) => {
      body += chunk;
    });

    req.on("end", async () => {
      try {
        const payload = JSON.parse(body || "{}");
        const result = await analyzeUrl(payload.url);
        sendJson(res, 200, result);
      } catch (error) {
        sendJson(res, 400, { error: error.message || "Failed to analyze URL." });
      }
    });

    return;
  }

  res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("Not found");
});

server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
