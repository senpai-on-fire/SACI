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

# Start Vite dev server in web directory
cd web

# Check if node_modules exists, if not run npm install
if [ ! -d "node_modules" ]; then
    echo "Installing npm dependencies..."
    npm install
fi

# Build static assets for FastAPI to serve
echo "Building static assets..."
npm run build

# Start FastAPI server
cd ..
echo "Starting FastAPI server on port 8000..."
fastapi dev saci/webui/web.py --host 127.0.0.1 --port 8000 &
FASTAPI_PID=$!

# Wait for FastAPI to start
sleep 2

# Start Vite dev server
cd web
echo "Starting Vite development server on port 5173..."
npm run dev

# Keep script running
wait $FASTAPI_PID
