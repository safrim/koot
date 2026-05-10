import asyncio
import json
import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Initialize the Sidecar API
app = FastAPI(
    title="koot Local API Bridge",
    description="Localhost REST sidecar bridging web/UI clients to the koot IPC socket.",
    version="1.0.0"
)

# Target the IPC Gateway established in Session 11/12
SOCKET_PATH = os.getenv("KOOT_IPC_SOCKET", "/tmp/koot.sock")

class BridgeRequest(BaseModel):
    action: str
    payload: dict = {}

async def forward_to_ipc(action: str, payload: dict) -> dict:
    """Opens a volatile connection to the Unix Socket and proxies the payload."""
    if not os.path.exists(SOCKET_PATH):
        raise HTTPException(
            status_code=503, 
            detail="koot Core IPC socket not found. Is the daemon running?"
        )

    try:
        reader, writer = await asyncio.open_unix_connection(SOCKET_PATH)
        
        request_data = {
            "action": action,
            "payload": payload
        }
        
        # Dispatch to the core
        writer.write(json.dumps(request_data).encode())
        await writer.drain()

        # Await core response
        data = await reader.read(4096)
        writer.close()
        await writer.wait_closed()

        return json.loads(data.decode())
        
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"IPC Gateway Communication Error: {str(e)}"
        )

@app.post("/api/v1/invoke")
async def invoke_command(request: BridgeRequest):
    """
    Primary endpoint for UI clients to interact with the koot Core.
    Example payload: {"action": "vault.get", "payload": {"uuid": "1234"}}
    """
    response = await forward_to_ipc(request.action, request.payload)
    return response

if __name__ == "__main__":
    import uvicorn
    # This allows running the file directly via `python koot/network/api/local_bridge.py`
    uvicorn.run("koot.network.api.local_bridge:app", host="127.0.0.1", port=8080, reload=True)