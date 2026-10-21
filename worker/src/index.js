/**
 * Cloudflare Worker that checks MCP tool definitions for high-signal risks.
 *
 * POST /check
 * Body: { "tools": [ { "name": "...", "description": "...", "inputSchema": {...} } ] }
 */

const STEERING = [
  /ignore previous/i,
  /before using this tool/i,
  /first call/i,
  /you must/i,
  /override/i,
];

const SENSITIVE = [
  /~\/\.ssh/i,
  /~\/\.aws/i,
  /\.env/i,
  /id_rsa/i,
  /credentials/i,
];

const BROAD = [
  /shell/i,
  /execute command/i,
  /run arbitrary/i,
];

const UNPINNED = [
  /npx\s+[^\s]+@latest/i,
  /uvx\s+[^\s]+/i,
  /docker\s+run\s+[^\s]+:latest/i,
];

const OPEN_URL = [
  /fetch any url/i,
  /from any url/i,
  /call the provided endpoint/i,
  /request the given url/i,
  /arbitrary url/i,
  /webhook url/i,
];

const BROAD_FS = [
  /rooted at \//i,
  /root.*\$home/i,
  /filesystem.*home/i,
  /access to the entire filesystem/i,
];

const RISKY_PARAMS = new Set(["url", "endpoint", "webhook", "host", "path", "filepath", "file_path"]);

const MAX_BODY_BYTES = 100_000;
const MAX_TOOLS = 50;
// Longer descriptions are flagged and only this prefix is pattern-matched, which
// bounds regex work without ever reporting an oversized tool as clean.
const MAX_DESCRIPTION_CHARS = 10_000;

const JSON_HEADERS = {
  "content-type": "application/json",
  "x-content-type-options": "nosniff",
  "cache-control": "no-store",
};

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload, null, 2), { status, headers: JSON_HEADERS });
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Read the body with a hard byte cap; Content-Length is optional and untrusted. */
async function readBody(request) {
  const declared = Number.parseInt(request.headers.get("content-length") || "0", 10);
  if (declared > MAX_BODY_BYTES) return null;
  if (!request.body) return "";

  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

/** Return an error message for a malformed request, or null if it can be scanned. */
function validate(body) {
  if (!isObject(body) || !Array.isArray(body.tools)) return 'Body must be an object with a "tools" array';
  if (body.tools.length > MAX_TOOLS) return "Too many tools";
  for (const [i, tool] of body.tools.entries()) {
    if (!isObject(tool)) return `tools[${i}] must be an object`;
    if (tool.description !== undefined && typeof tool.description !== "string") {
      return `tools[${i}].description must be a string`;
    }
  }
  return null;
}

function scanTool(tool) {
  const desc = tool.description ?? "";
  const findings = [];
  if (desc.length > MAX_DESCRIPTION_CHARS) {
    findings.push({
      severity: "high",
      type: "description_too_long",
      length: desc.length,
      limit: MAX_DESCRIPTION_CHARS,
    });
  }
  findings.push(...checkDescription(desc.slice(0, MAX_DESCRIPTION_CHARS)));
  findings.push(...checkSchema(tool.inputSchema || tool.input_schema));
  return findings;
}

function checkDescription(desc) {
  const findings = [];
  for (const re of STEERING) {
    if (re.test(desc)) findings.push({ severity: "high", type: "steering_language" });
  }
  for (const re of SENSITIVE) {
    if (re.test(desc)) findings.push({ severity: "high", type: "sensitive_path_reference" });
  }
  for (const re of BROAD) {
    if (re.test(desc)) findings.push({ severity: "medium", type: "broad_capability" });
  }
  for (const re of UNPINNED) {
    if (re.test(desc)) findings.push({ severity: "medium", type: "unpinned_package" });
  }
  for (const re of OPEN_URL) {
    if (re.test(desc)) findings.push({ severity: "high", type: "open_url_argument" });
  }
  for (const re of BROAD_FS) {
    if (re.test(desc)) findings.push({ severity: "medium", type: "broad_filesystem_root" });
  }
  return findings;
}

function checkSchema(schema) {
  const findings = [];
  if (!schema || typeof schema !== "object") return findings;
  const props = schema.properties || {};
  for (const [name, prop] of Object.entries(props)) {
    if (!prop || prop.type !== "string") continue;
    if (RISKY_PARAMS.has(name.toLowerCase()) && !prop.enum && !prop.pattern) {
      findings.push({
        severity: "medium",
        type: "unconstrained_risky_parameter",
        parameter: name,
      });
    }
  }
  return findings;
}

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/") {
      return new Response(
        "agent-mcp-secure check endpoint. POST /check with JSON body { tools: [...] }",
        {
          headers: {
            "content-type": "text/plain",
            "x-content-type-options": "nosniff",
          },
        }
      );
    }

    if (request.method !== "POST" || url.pathname !== "/check") {
      return new Response("Not found", { status: 404 });
    }

    const text = await readBody(request);
    if (text === null) return jsonResponse({ error: "Request too large" }, 413);

    let body;
    try {
      body = JSON.parse(text);
    } catch {
      return jsonResponse({ error: "Invalid JSON" }, 400);
    }

    // Fail closed: anything that is not a well-formed tool list is rejected,
    // never scanned as an empty list and reported clean.
    const error = validate(body);
    if (error) return jsonResponse({ error }, 400);

    const results = [];
    for (const tool of body.tools) {
      const findings = scanTool(tool);
      if (findings.length) {
        results.push({ tool: typeof tool.name === "string" && tool.name ? tool.name : "unknown", findings });
      }
    }

    return jsonResponse({ results });
  },
};
