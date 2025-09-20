import asyncio
import os
import websockets

# Render provides a PORT environment variable, fallback to 10000 if missing
PORT = int(os.environ.get("PORT", 10000))

async def handler(websocket):
    print("🔌 Client connected")

    # Send welcome message
    await websocket.send("Hello! You are connected to the Render WebSocket server.")

    try:
        async for message in websocket:
            print(f"📩 Received: {message}")
            # Echo message back
            await websocket.send(f"Echo: {message}")
    except websockets.ConnectionClosed:
        print("❌ Client disconnected")

async def main():
    async with websockets.serve(handler, "0.0.0.0", PORT):
        print(f"🚀 WebSocket server running on port {PORT}")
        await asyncio.Future()  # keep running forever

if __name__ == "__main__":
    asyncio.run(main())
