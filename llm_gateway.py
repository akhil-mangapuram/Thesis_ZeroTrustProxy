# llm_gateway.py (Updates)
import os
from google import genai
from google.genai import types
from dotenv import load_dotenv

load_dotenv()

class LLMGateway:
    def __init__(self, model_id: str = None):
        self.client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
        self.model_id = model_id or os.getenv("GEMINI_MODEL") or os.getenv("GEMINI_LLM") or "gemini-3.8-flash" 

    def _convert_mcp_to_gemini_tools(self, mcp_tools) -> list[types.Tool]:
        function_declarations = []
        for mcp_tool in mcp_tools:
            func_decl = types.FunctionDeclaration(
                name=mcp_tool.name,
                description=mcp_tool.description,
                parameters=mcp_tool.input_schema 
            )
            function_declarations.append(func_decl)
        return [types.Tool(function_declarations=function_declarations)]

    def start_agent_session(self, mcp_tools_list, system_instruction: str = None):
        """Starts a multi-turn chat session so the agent remembers context across tool calls."""
        gemini_tools = self._convert_mcp_to_gemini_tools(mcp_tools_list)
        print("[LLM Gateway] Starting agent session with tools:", [decl.name for tool in gemini_tools for decl in tool.function_declarations])
        
        # Ecologically valid enterprise system instruction (aligned with Section 3.6)
        instruction = system_instruction or (
            "You are an enterprise AI assistant with access to internal workspace tools. "
            "Use the available tools to fulfill user requests efficiently and accurately."
        )
        
        config = types.GenerateContentConfig(
            temperature=0.0,
            top_p=0.0,
            top_k=1,
            seed=42,
            tools=gemini_tools,
            system_instruction=instruction
        )
        # Utilize a chat session to maintain context across successive tool invocations.
        return self.client.chats.create(model=self.model_id, config=config)