from __future__ import annotations

import logging
import uuid

from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, TextContent, Tool

from .registry import ToolRegistry
from .serialization import tool_text


async def serve(config):
    logging.basicConfig(level=logging.WARNING)
    registry = ToolRegistry(config)
    server = Server('localguard',version='0.1.0')
    session_id = uuid.uuid4().hex

    @server.list_tools()
    async def list_tools():
        return [Tool(**definition) for definition in registry.describe()]

    @server.call_tool(validate_input=False)
    async def call_tool(name, arguments):
        client = server.request_context.session.client_params
        client_name = client.clientInfo.name if client else 'unknown MCP client'
        result = await registry.call(name,arguments,session_id,client_name)
        if result['isError']:
            return CallToolResult(isError=True, structuredContent=result['data'] or None,
                                  content=[TextContent(type='text',text=result['error'])])
        data = result['data']
        return CallToolResult(isError=False,structuredContent=data,
                              content=[TextContent(type='text',text=tool_text(data))])

    registry.engine.start()
    try:
        async with stdio_server() as (read_stream,write_stream):
            await server.run(read_stream,write_stream,server.create_initialization_options())
    finally:
        await registry.close()
