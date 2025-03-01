#!/bin/bash

# Kill any existing servers on exit
trap 'kill $(jobs -p)' EXIT

# Print helpful banner
echo "=============================================================="
echo "🚀 SACI Development Environment"
echo "=============================================================="
echo "📝 IMPORTANT: For development with Hot Module Replacement:"
echo "   Access your app at: http://localhost:5173"
echo "   (NOT at http://localhost:8000)"
echo "=============================================================="

# Start FastAPI server
echo "Starting FastAPI server on port 8000..."
fastapi dev saci/webui/web.py --host 127.0.0.1 --port 8000 &
FASTAPI_PID=$!

# Wait for FastAPI to start
sleep 2

# Start Vite dev server in web directory
cd web
echo "Starting Vite development server on port 5173..."
npm run dev

# Keep script running
wait $FASTAPI_PID
