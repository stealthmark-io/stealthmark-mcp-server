# StealthMark MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io) server that gives AI agents access to the StealthMark API over stdio.

## Tools

| Tool | What it does | API call |
|---|---|---|
| `gateway_resolve` | Resolves a website's machine-readable agent manifest and its exposed actions. | `POST /v1/gateway/resolve` |
| `gateway_invoke` | Invokes an action a site declares in its agent manifest. | `POST /v1/gateway/invoke` |
| `kya_status` | Looks up an agent's passport status. | `GET /v1/kya/verify` |

## Configuration

| Setting | Flag | Environment variable | Default |
|---|---|---|---|
| API base URL | `--api-url=<url>` | `STEALTHMARK_API_URL` | `http://localhost:3001` |
| API key, sent as a Bearer token | `--api-key=<key>` | `STEALTHMARK_API_KEY` | none |

Flags take precedence over environment variables.

## Build and run

```bash
npm ci
npm run build
node dist/index.js --api-url=<your StealthMark API URL>
```

Example MCP client entry:

```json
{
  "mcpServers": {
    "stealthmark": {
      "command": "node",
      "args": ["/absolute/path/to/stealthmark-mcp-server/dist/index.js"],
      "env": {
        "STEALTHMARK_API_URL": "<your StealthMark API URL>",
        "STEALTHMARK_API_KEY": "<your API key>"
      }
    }
  }
}
```

## Development

```bash
npm run typecheck
npm test
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
