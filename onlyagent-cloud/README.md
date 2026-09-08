# OnlyAgent Cloud MVP

Serverless relay and remote MCP endpoint for OnlyAgent.

## Architecture

```text
Hermes / OpenClaw / MCP client
        |
        | Streamable HTTP + device-scoped bearer grant
        v
mcp.onlyagent.app/mcp
        |
        v
Cloudflare Worker
        |
        v
DeviceSession Durable Object
        |
        | WebSocket
        v
onlyagent.app browser (later: T113-S4 standalone)
        |
        v
WebHID / OnlyAgent hardware
```

The MVP is deliberately Durable-Object-only: it does not require D1 or a traditional server.

## Device authentication

On first connection the browser registers a random device ID and receives a high-entropy `oad_...` device credential. Only its SHA-256 hash is stored in the Durable Object. The browser stores the raw credential locally for the MVP.

The device credential can mint:

- a short-lived one-time WebSocket connection token;
- scoped, expiring remote-agent tokens of the form `oa1.<device-id>.<random>`.

Agent tokens are stored only as hashes and are scoped to one device.

Production will replace browser-local device ownership with OnlyKey-backed identity plus OAuth, without changing the MCP tool surface.

## MCP tools

- `computer_get_state`
- `computer_screenshot`
- `computer_click`
- `computer_double_click`
- `computer_move`
- `computer_drag`
- `computer_scroll`
- `computer_type`
- `computer_key`
- `computer_hotkey`
- `computer_wait`
- `computer_stop`

## Domains

Wrangler configures the Worker as the origin for:

- `api.onlyagent.app`
- `mcp.onlyagent.app`

Allowed browser origins are restricted to the official OnlyAgent origins in `wrangler.jsonc`.

## Local development

```bash
cd onlyagent-cloud
npm install
npm run dev
```

## CI deployment

The repository workflow uses two GitHub Actions secrets:

- `CLOUDFLARE_ACCOUNT_ID`
- `CLOUDFLARE_API_TOKEN`

The Cloudflare token should be created from the **Edit Cloudflare Workers** template and scoped to the account/zone containing `onlyagent.app`.
