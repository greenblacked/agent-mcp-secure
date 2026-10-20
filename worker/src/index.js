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
  /fetch\w*\b[^.]{0,40}\bany\s+url/i,
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

    // Basic size limit
    const len = parseInt(request.headers.get("content-length") || "0", 10);
    if (len > 100_000) {
      return new Response(JSON.stringify({ error: "Request too large" }), {
        status: 413,
        headers: { "content-type": "application/json" },
      });
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return new Response(JSON.stringify({ error: "Invalid JSON" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      });
    }

    const tools = Array.isArray(body.tools) ? body.tools : [];
    if (tools.length > 50) {
      return new Response(JSON.stringify({ error: "Too many tools" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      });
    }

    const results = [];
    for (const tool of tools) {
      const name = tool.name || "unknown";
      const desc = typeof tool.description === "string" ? tool.description : "";
      if (desc.length > 10000) continue;

      const findings = checkDescription(desc);
      const schema = tool.inputSchema || tool.input_schema;
      findings.push(...checkSchema(schema));

      if (findings.length) results.push({ tool: name, findings });
    }

    return new Response(JSON.stringify({ results }, null, 2), {
      headers: {
        "content-type": "application/json",
        "x-content-type-options": "nosniff",
        "cache-control": "no-store",
      },
    });
  },
};
