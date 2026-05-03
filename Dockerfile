# ── Stage 1: Build React frontend ───────────────────────────────────────────
FROM node:20-alpine AS frontend
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ── Stage 2: Build Go backend ────────────────────────────────────────────────
FROM golang:1.22-alpine AS backend
WORKDIR /app
# gcc + musl-dev required for CGO (go-sqlite3)
RUN apk add --no-cache gcc musl-dev
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
RUN CGO_ENABLED=1 GOOS=linux go build -o server .

# ── Stage 3: Final image ─────────────────────────────────────────────────────
FROM alpine:3.19
WORKDIR /app
RUN apk add --no-cache ca-certificates tzdata libgcc

COPY --from=backend /app/server ./server
COPY --from=backend /app/data ./data
COPY --from=frontend /app/frontend/dist ./frontend/dist

ENV PORT=8080
ENV DATA_DIR=./data
ENV DB_PATH=./cps_dashboard.db
ENV STATIC_DIR=./frontend/dist
ENV GIN_MODE=release

EXPOSE 8080
CMD ["./server"]
