# MCP-Server-Personal-Assistant-Job-Application-tracker
MCP server to track your schedule and Job Applications

## MCP Client Configuration

To connect to the **personal-assistant** MCP server, add the following block to your settings (e.g. in `settings.json`):

```json
{
  "mcpServers": {
    "personal-assistant": {
      "command": "node",
      "args": [
        "C:\\Users\\<YOUR_USER>\\Desktop\\personal-assistant-mcp\\dist\\server.js"
      ],
      "env": {
        "GOOGLE_CLIENT_ID": "<YOUR_GOOGLE_CLIENT_ID>",
        "GOOGLE_CLIENT_SECRET": "<YOUR_GOOGLE_CLIENT_SECRET>"
      }
    }
  }
}
