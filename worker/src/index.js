/**
 * Cloudflare Worker that checks MCP tool definitions for high-signal risks.
 *
 * POST /check
 * Body: { "tools": [ { "name": "...", "description": "..." } ] }
 *
 * Returns findings for steering language, sensitive paths, and broad capabilities.
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
  return findings;
}

export default {
  async fetch(request) {
    if (request.method === "GET" && new URL(request.url).pathname === "/") {
      return new Response(
        "agent-mcp-secure check endpoint. POST /check with JSON body { tools: [...] }",
        { headers: { "content-type": "text/plain" } }
      );
    }

    if (request.method !== "POST" || new URL(request.url).pathname !== "/check") {
      return new Response("Not found", { status: 404 });
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
      if (findings.length) results.push({ tool: name, findings });
    }

    return new Response(JSON.stringify({ results }, null, 2), {
      headers: { "content-type": "application/json" },
    });
  },
};
