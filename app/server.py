"""MCP Policy Gateway server."""
import uvicorn
from fastapi import FastAPI
from pkg.api.routes import router

app = FastAPI(title="MCP Policy Gateway", version="0.1.0")
app.include_router(router)

if __name__ == "__main__":
    uvicorn.run("app.server:app", host="0.0.0.0", port=8400, reload=True)
