import { DurableObject } from "cloudflare:workers";
import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { z } from "zod";

const MAX_AGENT_TTL_DAYS = 90;
const WS_TOKEN_TTL_MS = 5 * 60 * 1000;

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);

      if (url.pathname === "/health") {
        return json({ ok: true, service: "onlyagent-cloud", time: new Date().toISOString() });
      }

      if (url.pathname === "/mcp") {
        return handleMcp(request, env, ctx);
      }

      if (url.pathname.startsWith("/api/")) {
        const originError = browserOriginError(request, env);
        if (originError) return originError;
        if (request.method === "OPTIONS") return cors(new Response(null, { status: 204 }), request, env);
        return cors(await handleApi(request, env), request, env);
      }

      if (url.pathname.startsWith("/device/ws/")) {
        const originError = browserOriginError(request, env);
        if (originError) return originError;
        return handleDeviceWebSocket(request, env);
      }

      return new Response("Not found", { status: 404 });
    } catch (error) {
      console.error(error);
      return json({ error: error?.message || "Internal error" }, error?.status || 500);
    }
  },
};

async function handleApi(request, env) {
  const url = new URL(request.url);
  const parts = url.pathname.split("/").filter(Boolean);

  if (url.pathname === "/api/devices" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    const deviceId = `oa_${randomSegment(18)}`;
    const deviceSecret = `oad_${randomSegment(32)}`;
    const stub = deviceStub(env, deviceId);
    const response = await stub.fetch("https://device/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        deviceId,
        name: String(body.name || "OnlyAgent Browser Device").slice(0, 80),
        secretHash: await sha256Hex(deviceSecret),
      }),
    });
    if (!response.ok) return response;
    return json({ device: { id: deviceId, name: String(body.name || "OnlyAgent Browser Device").slice(0, 80), secret: deviceSecret } }, 201);
  }

  if (parts[0] === "api" && parts[1] === "devices" && parts[2]) {
    const deviceId = parts[2];
    const secret = bearer(request);
    if (!secret?.startsWith("oad_")) return json({ error: "Device authentication required" }, 401);
    const stub = deviceStub(env, deviceId);

    if (parts[3] === "ws-token" && parts.length === 4 && request.method === "POST") {
      return stub.fetch("https://device/ws-token", {
        method: "POST",
        headers: { authorization: `Bearer ${secret}` },
      });
    }

    if (parts[3] === "grants" && parts.length === 4 && request.method === "POST") {
      const body = await request.json().catch(() => ({}));
      const scopes = sanitizeScopes(body.scopes);
      if (!scopes.length) return json({ error: "At least one scope is required" }, 400);
      const ttlDays = Math.max(1, Math.min(Number(body.ttl_days || 7), MAX_AGENT_TTL_DAYS));
      return stub.fetch("https://device/grants", {
        method: "POST",
        headers: { authorization: `Bearer ${secret}`, "content-type": "application/json" },
        body: JSON.stringify({
          name: String(body.name || "Remote Agent").slice(0, 80),
          scopes,
          ttlDays,
        }),
      });
    }
  }

  return json({ error: "Not found" }, 404);
}

async function handleDeviceWebSocket(request, env) {
  if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
    return new Response("Expected WebSocket", { status: 426 });
  }
  const url = new URL(request.url);
  const deviceId = decodeURIComponent(url.pathname.split("/").pop());
  const token = url.searchParams.get("token");
  if (!deviceId || !token) return new Response("Unauthorized", { status: 401 });
  const stub = deviceStub(env, deviceId);
  const target = new URL("https://device/ws");
  target.searchParams.set("token", token);
  return stub.fetch(new Request(target, request));
}

async function handleMcp(request, env, ctx) {
  const token = bearer(request);
  const deviceId = parseAgentDeviceId(token);
  if (!deviceId) return mcpUnauthorized();

  const stub = deviceStub(env, deviceId);
  const authResponse = await stub.fetch("https://device/auth-grant", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token }),
  });
  if (!authResponse.ok) return mcpUnauthorized();
  const grant = await authResponse.json();

  const rpc = async (command, params = {}) => {
    const response = await stub.fetch("https://device/rpc", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ command, params }),
    });

    if (response.headers.get("x-onlyagent-kind") === "image") {
      if (!response.ok) return { ok: false, error: await response.text() };
      return {
        ok: true,
        kind: "image",
        mime: response.headers.get("content-type") || "image/jpeg",
        width: Number(response.headers.get("x-onlyagent-width") || 0),
        height: Number(response.headers.get("x-onlyagent-height") || 0),
        bytes: new Uint8Array(await response.arrayBuffer()),
      };
    }

    return response.json().catch(() => ({ ok: false, error: response.statusText || "Device RPC failed" }));
  };

  const handler = createMcpHandler(() => createOnlyAgentMcp({ grant, rpc }), {
    legacy: "stateless",
    responseMode: "auto",
  });
  return handler(request, env, ctx);
}

function createOnlyAgentMcp({ grant, rpc }) {
  const server = new McpServer({ name: "OnlyAgent", version: "0.1.0" }, { capabilities: { tools: {} } });
  const has = (scope) => grant.scopes.includes(scope);

  if (has("state.read")) {
    server.registerTool("computer_get_state", {
      description: "Get the current OnlyAgent device and capture/control state.",
      inputSchema: {},
    }, async () => textResult(await rpcChecked(rpc, "get_state", {})));
  }

  if (has("screen.read")) {
    server.registerTool("computer_screenshot", {
      description: "Capture the current target computer screen using browser or hardware capture.",
      inputSchema: {
        max_width: z.number().int().min(320).max(3840).optional(),
        quality: z.number().int().min(20).max(95).optional(),
      },
    }, async ({ max_width = 1280, quality = 75 }) => {
      const result = await rpc("screenshot", { max_width, quality });
      if (!result || result.kind !== "image" || !result.bytes) throw new Error(result?.error || "No screenshot returned");
      return { content: [{ type: "image", data: bytesToBase64(result.bytes), mimeType: result.mime || "image/jpeg" }] };
    });
  }

  if (has("input.control")) {
    server.registerTool("computer_click", {
      description: "Click at screenshot coordinates.",
      inputSchema: { x: z.number(), y: z.number(), button: z.enum(["left", "right", "middle"]).optional(), count: z.number().int().min(1).max(3).optional() },
    }, async ({ x, y, button = "left", count = 1 }) => textResult(await rpcChecked(rpc, "click", { x, y, button, count })));

    server.registerTool("computer_double_click", {
      description: "Double-click at screenshot coordinates.",
      inputSchema: { x: z.number(), y: z.number(), button: z.enum(["left", "right", "middle"]).optional() },
    }, async ({ x, y, button = "left" }) => textResult(await rpcChecked(rpc, "click", { x, y, button, count: 2 })));

    server.registerTool("computer_move", {
      description: "Move the pointer to screenshot coordinates.",
      inputSchema: { x: z.number(), y: z.number() },
    }, async ({ x, y }) => textResult(await rpcChecked(rpc, "move", { x, y })));

    server.registerTool("computer_drag", {
      description: "Drag from one screenshot coordinate to another.",
      inputSchema: { from_x: z.number(), from_y: z.number(), to_x: z.number(), to_y: z.number(), button: z.enum(["left", "right", "middle"]).optional() },
    }, async ({ from_x, from_y, to_x, to_y, button = "left" }) => textResult(await rpcChecked(rpc, "drag", { from_x, from_y, to_x, to_y, button })));

    server.registerTool("computer_scroll", {
      description: "Scroll the target computer.",
      inputSchema: { delta_x: z.number().optional(), delta_y: z.number() },
    }, async ({ delta_x = 0, delta_y }) => textResult(await rpcChecked(rpc, "scroll", { delta_x, delta_y })));

    server.registerTool("computer_type", {
      description: "Type text through OnlyAgent's USB HID keyboard.",
      inputSchema: { text: z.string().max(10000) },
    }, async ({ text }) => textResult(await rpcChecked(rpc, "type", { text })));

    server.registerTool("computer_key", {
      description: "Press a single key.",
      inputSchema: { key: z.string().min(1).max(64) },
    }, async ({ key }) => textResult(await rpcChecked(rpc, "key", { key })));

    server.registerTool("computer_hotkey", {
      description: "Press a keyboard shortcut such as CTRL+L.",
      inputSchema: { keys: z.array(z.string().min(1).max(64)).min(2).max(8) },
    }, async ({ keys }) => textResult(await rpcChecked(rpc, "hotkey", { keys })));

    server.registerTool("computer_wait", {
      description: "Wait for the target computer to settle before the next observation.",
      inputSchema: { milliseconds: z.number().int().min(0).max(30000) },
    }, async ({ milliseconds }) => textResult(await rpcChecked(rpc, "wait", { milliseconds })));
  }

  if (has("session.stop")) {
    server.registerTool("computer_stop", {
      description: "Emergency-stop remote control and release all pressed keys/buttons.",
      inputSchema: {},
    }, async () => textResult(await rpcChecked(rpc, "stop", {})));
  }

  return server;
}

async function rpcChecked(rpc, command, params) {
  const result = await rpc(command, params);
  if (!result || result.ok === false) throw new Error(result?.error || `OnlyAgent command failed: ${command}`);
  return result.result ?? { ok: true };
}

function textResult(value) {
  return { content: [{ type: "text", text: typeof value === "string" ? value : JSON.stringify(value) }] };
}

function mcpUnauthorized() {
  return new Response("Unauthorized", {
    status: 401,
    headers: { "www-authenticate": 'Bearer realm="OnlyAgent MCP"', "cache-control": "no-store" },
  });
}

function parseAgentDeviceId(token) {
  if (!token) return null;
  const match = /^oa1\.([A-Za-z0-9_-]+)\.[A-Za-z0-9_-]+$/.exec(token);
  return match ? match[1] : null;
}

function sanitizeScopes(input) {
  const allowed = new Set(["screen.read", "input.control", "state.read", "session.stop"]);
  const values = Array.isArray(input) ? input : [...allowed];
  return [...new Set(values.filter((scope) => allowed.has(scope)))];
}

function deviceStub(env, deviceId) {
  return env.DEVICE_SESSIONS.get(env.DEVICE_SESSIONS.idFromName(deviceId));
}

function bearer(request) {
  const value = request.headers.get("authorization") || "";
  return value.startsWith("Bearer ") ? value.slice(7).trim() : null;
}

function allowedOrigins(env) {
  return new Set(String(env.ALLOWED_ORIGINS || "").split(",").map((x) => x.trim()).filter(Boolean));
}

function browserOriginError(request, env) {
  const origin = request.headers.get("origin");
  if (!origin || !allowedOrigins(env).has(origin)) return new Response("Origin not allowed", { status: 403 });
  return null;
}

function cors(response, request, env) {
  const origin = request.headers.get("origin");
  if (!origin || !allowedOrigins(env).has(origin)) return response;
  const headers = new Headers(response.headers);
  headers.set("access-control-allow-origin", origin);
  headers.set("vary", "Origin");
  headers.set("access-control-allow-methods", "GET, POST, DELETE, OPTIONS");
  headers.set("access-control-allow-headers", "Authorization, Content-Type");
  headers.set("access-control-max-age", "86400");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function randomSegment(bytes = 32) {
  const value = new Uint8Array(bytes);
  crypto.getRandomValues(value);
  return base64Url(value);
}

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (let i = 0; i < arr.length; i += 0x8000) binary += String.fromCharCode(...arr.subarray(i, i + 0x8000));
  return btoa(binary);
}

function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
}

export class DeviceSession extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.pending = new Map();
  }

  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/register" && request.method === "POST") {
      const existing = await this.ctx.storage.get("device");
      if (existing) return json({ error: "Device already registered" }, 409);
      const body = await request.json();
      await this.ctx.storage.put("device", {
        id: body.deviceId,
        name: body.name,
        secretHash: body.secretHash,
        createdAt: Date.now(),
      });
      return json({ ok: true }, 201);
    }

    if (url.pathname === "/ws-token" && request.method === "POST") {
      if (!(await this.verifyDeviceRequest(request))) return json({ error: "Unauthorized" }, 401);
      const token = `oaw_${randomSegment(32)}`;
      await this.ctx.storage.put("wsToken", {
        hash: await sha256Hex(token),
        expiresAt: Date.now() + WS_TOKEN_TTL_MS,
      });
      return json({ token, expires_in: WS_TOKEN_TTL_MS / 1000 });
    }

    if (url.pathname === "/grants" && request.method === "POST") {
      if (!(await this.verifyDeviceRequest(request))) return json({ error: "Unauthorized" }, 401);
      const device = await this.ctx.storage.get("device");
      const body = await request.json();
      const token = `oa1.${device.id}.${randomSegment(32)}`;
      const hash = await sha256Hex(token);
      const grant = {
        name: body.name,
        scopes: sanitizeScopes(body.scopes),
        createdAt: Date.now(),
        expiresAt: Date.now() + Number(body.ttlDays || 7) * 86400000,
      };
      await this.ctx.storage.put(`grant:${hash}`, grant);
      return json({ grant: { token, device_id: device.id, ...grant } }, 201);
    }

    if (url.pathname === "/auth-grant" && request.method === "POST") {
      const { token } = await request.json();
      const hash = await sha256Hex(String(token || ""));
      const grant = await this.ctx.storage.get(`grant:${hash}`);
      if (!grant || Number(grant.expiresAt) <= Date.now()) {
        if (grant) await this.ctx.storage.delete(`grant:${hash}`);
        return json({ error: "Invalid or expired grant" }, 401);
      }
      return json({ scopes: grant.scopes, name: grant.name, expiresAt: grant.expiresAt });
    }

    if (url.pathname === "/ws") {
      if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") return new Response("Expected WebSocket", { status: 426 });
      const supplied = url.searchParams.get("token") || "";
      const expected = await this.ctx.storage.get("wsToken");
      if (!expected || expected.expiresAt <= Date.now() || (await sha256Hex(supplied)) !== expected.hash) {
        return new Response("Invalid or expired WebSocket token", { status: 401 });
      }
      await this.ctx.storage.delete("wsToken");

      for (const old of this.ctx.getWebSockets("device")) {
        try { old.close(4001, "Replaced by a newer OnlyAgent connection"); } catch {}
      }

      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      this.ctx.acceptWebSocket(server, ["device"]);
      server.serializeAttachment({ role: "device" });
      return new Response(null, { status: 101, webSocket: client });
    }

    if (url.pathname === "/rpc" && request.method === "POST") {
      const sockets = this.ctx.getWebSockets("device").filter((ws) => ws.readyState === WebSocket.OPEN);
      if (!sockets.length) return json({ ok: false, error: "OnlyAgent device is offline" }, 503);

      const { command, params = {} } = await request.json();
      const id = crypto.randomUUID();
      const ws = sockets[0];
      const result = await new Promise((resolve) => {
        const timeout = setTimeout(() => {
          this.pending.delete(id);
          resolve({ ok: false, error: `Device command timed out: ${command}`, status: 504 });
        }, command === "screenshot" ? 30000 : 15000);
        this.pending.set(id, { resolve, timeout });
        ws.send(JSON.stringify({ type: "command", id, command, params }));
      });

      if (result.kind === "image") {
        return new Response(result.bytes, {
          status: 200,
          headers: {
            "content-type": result.mime || "image/jpeg",
            "x-onlyagent-kind": "image",
            "x-onlyagent-width": String(result.width || 0),
            "x-onlyagent-height": String(result.height || 0),
            "cache-control": "no-store",
          },
        });
      }
      return json(result, result.status || (result.ok === false ? 502 : 200));
    }

    if (url.pathname === "/status") {
      return json({
        online: this.ctx.getWebSockets("device").some((ws) => ws.readyState === WebSocket.OPEN),
        state: (await this.ctx.storage.get("lastStatus")) || null,
      });
    }

    return new Response("Not found", { status: 404 });
  }

  async verifyDeviceRequest(request) {
    const token = bearer(request);
    if (!token?.startsWith("oad_")) return false;
    const device = await this.ctx.storage.get("device");
    return !!device && (await sha256Hex(token)) === device.secretHash;
  }

  async webSocketMessage(ws, message) {
    if (typeof message === "string") {
      let payload;
      try { payload = JSON.parse(message); } catch { return; }
      if (payload.type === "status") {
        await this.ctx.storage.put("lastStatus", { ...payload.state, received_at: Date.now() });
        return;
      }
      if (payload.type === "result" && payload.id) {
        this.resolvePending(payload.id, { ok: payload.ok !== false, result: payload.result, error: payload.error });
      }
      return;
    }

    const bytes = new Uint8Array(message);
    if (bytes.byteLength < 5) return;
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const headerLength = view.getUint32(0, true);
    if (headerLength <= 0 || 4 + headerLength > bytes.byteLength) return;

    let header;
    try { header = JSON.parse(new TextDecoder().decode(bytes.subarray(4, 4 + headerLength))); } catch { return; }
    if (header.type !== "screenshot" || !header.id) return;

    this.resolvePending(header.id, {
      ok: true,
      kind: "image",
      mime: header.mime || "image/jpeg",
      width: header.width,
      height: header.height,
      bytes: bytes.slice(4 + headerLength),
    });
  }

  async webSocketClose() {
    this.failPending("Device disconnected");
  }

  async webSocketError() {
    this.failPending("Device WebSocket error");
  }

  failPending(error) {
    for (const [id, pending] of this.pending) {
      clearTimeout(pending.timeout);
      pending.resolve({ ok: false, error, status: 503 });
      this.pending.delete(id);
    }
  }

  resolvePending(id, value) {
    const pending = this.pending.get(id);
    if (!pending) return;
    clearTimeout(pending.timeout);
    this.pending.delete(id);
    pending.resolve(value);
  }
}
