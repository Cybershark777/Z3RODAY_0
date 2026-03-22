#!/usr/bin/env bash
# CPS Threat Dashboard — Startup Script
# Starts Go backend (port 8001) and React frontend (port 3000)

set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "════════════════════════════════════════════"
echo "  CPS Threat Intelligence Dashboard v2.0"
echo "════════════════════════════════════════════"

# ── Go Backend ──────────────────────────────────────────────────────────────
echo ""
echo "▶ Starting Go backend on :8001"
cd "$ROOT/backend-go"

# Copy .env if exists in root
[ -f "$ROOT/.env" ] && cp "$ROOT/.env" .env

go run . &
BACKEND_PID=$!
echo "  Go backend PID: $BACKEND_PID"

# Wait for backend to be ready
sleep 2
echo "  ✔ Backend ready at http://localhost:8001"

# ── React Frontend ──────────────────────────────────────────────────────────
echo ""
echo "▶ Starting React frontend on :3000"
cd "$ROOT/frontend-react"
npm run dev &
FRONTEND_PID=$!
echo "  React frontend PID: $FRONTEND_PID"

echo ""
echo "════════════════════════════════════════════"
echo "  Dashboard: http://localhost:3000"
echo "  API:       http://localhost:8001/api/health"
echo "════════════════════════════════════════════"
echo ""
echo "Press Ctrl+C to stop both services"

# Cleanup on exit
trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; echo 'Stopped.'" EXIT

wait
