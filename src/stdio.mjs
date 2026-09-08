#!/usr/bin/env node
// Gmail for MCP clients that launch the server as a child process.
//
// Register it with:
//   claude mcp add gmail --scope user -- /path/to/gmail-mcp/src/stdio.mjs
//
// Claude Code reads ~/.claude.json, NOT claude_desktop_config.json. An entry
// in the desktop configuration is silently ignored by the CLI; the log then
// says "no stdio servers connected".

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { loeseKonfig, registriere } from './tools.mjs';

const server = new McpServer({ name: 'gmail', version: '1.0.0' });
registriere(server, loeseKonfig());

await server.connect(new StdioServerTransport());
