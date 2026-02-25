# Share a Secret (Project-Simulation)

A secure, "view-once" message and file sharing application. Users can share encrypted text messages or upload files that are automatically deleted after being viewed or downloaded once, or after a specified expiration time.

## 🚀 Features

- **End-to-End Encryption**: Messages are encrypted using AES-256-GCM before storage.
- **View-Once Logic**: Secrets are permanently deleted immediately after the first successful retrieval.
- **Self-Destruction**: Expired secrets are automatically cleaned up by a background scheduler (min-heap based).
- **Password Protection**: Every secret requires a password, hashed with bcrypt before storage.
- **Security Hardening**:
    - Max text/file size: 10MB
    - Password requirements: 6–72 characters
    - Expiration limit: Max 7 days
    - ID Validation: Strict UUID format checking on every request
- **Rate Limiting**: Protection against brute-force and spam (20 req/min per IP in production).
- **Real-time Monitoring**: Console dashboard for memory usage, GC stats, and secret deletion metrics.
- **Dual Frontend Support**:
    - Server-side rendered HTML (no JavaScript required)
    - JSON API for dynamic JS clients
- **Docker Ready**: All assets (HTML templates, CSS) are embedded into the binary via `go:embed` — no volume mounts needed for static files.

## 🛠 Tech Stack

| Layer       | Technology |
|-------------|-----------|
| Language    | [Go](https://go.dev/) 1.25.4 |
| Web Framework | [Fiber v2](https://gofiber.io/) |
| Templates   | Fiber HTML engine (`gofiber/template/html/v2`) |
| Database    | [SQLite](https://www.sqlite.org/) via [GORM](https://gorm.io/) + [glebarez/sqlite](https://github.com/glebarez/sqlite) (CGO) |
| File Storage | [MinIO](https://min.io/) (S3 Compatible) |
| Encryption  | `crypto/aes` (AES-256-GCM) |
| Password Hashing | `golang.org/x/crypto/bcrypt` |
| Serverless  | [AWS Lambda](https://aws.amazon.com/lambda/) via `aws-lambda-go-api-proxy` |

## 📋 Prerequisites

**Local development:**
- Go 1.25.4+
- GCC (for CGO/SQLite) — on Windows, use [TDM-GCC](https://jmeubank.github.io/tdm-gcc/)

**Docker deployment:**
- Docker

## ⚙️ Configuration

Create a `.env` file in the `backend/` directory:

```env
PORT=8080
FRONTEND_URL=http://localhost:8080
CORS_ALLOWED_ORIGINS=http://localhost:8080
ENCRYPTION_KEY=your-32-byte-secret-key-goes-here
APPDEBUG=0
```

| Variable | Description |
|----------|-------------|
| `PORT` | Port the server listens on |
| `FRONTEND_URL` | Base URL used to build shareable links |
| `CORS_ALLOWED_ORIGINS` | Allowed CORS origins for the JSON API |
| `ENCRYPTION_KEY` | **Must be exactly 32 bytes** (AES-256) |
| `APPDEBUG` | `0` = production (hard delete), `1` = debug (soft delete) |
| `MINIO_ENDPOINT` | The address to your MinIO container (e.g., `localhost:9000`) |
| `MINIO_ROOT_USER` | The root username to access MinIO |
| `MINIO_ROOT_PASSWORD` | The root password to access MinIO |

## 📂 Project Structure

```
Project-Simulation/
├── Dockerfile
├── backend/
│   ├── cmd/
│   │   ├── server/      # Main HTTP server entry point
│   │   ├── lambda/      # AWS Lambda entry point
│   │   ├── monitor/     # Real-time memory/metrics dashboard
│   │   ├── seeder/      # Stress-test DB seeder (500k secrets)
│   │   └── debug_db/    # Database inspection utility
│   ├── pkg/
│   │   ├── routes/      # HTTP handlers and route setup
│   │   ├── secret/      # Secret model
│   │   ├── encryption/  # AES-256-GCM encrypt/decrypt
│   │   └── heap/        # Min-heap based expiry scheduler
│   ├── views/           # HTML templates (embedded into binary)
│   │   ├── index.html
│   │   └── view.html
│   ├── static/          # Static assets (embedded into binary)
│   │   └── style.css
│   ├── templates.go     # go:embed declarations
│   └── .env
└── frontend/            # Legacy JS frontend (optional)
```

## 🐳 Docker Deployment (Recommended)

### Build the image

```bash
docker build -t my-go-app .
```

### Run the dependencies (MinIO Docker Container)

You must be running MinIO locally for file storage to work properly. Use this Docker command to spin up an ephemeral MinIO container on ports `9000` (API) and `9001` (Console):

```bash
docker run -p 9000:9000 -p 9001:9001 -e "MINIO_ROOT_USER=minioadmin" -e "MINIO_ROOT_PASSWORD=minioadmin" quay.io/minio/minio server /data --console-address ":9001"
```

### Run the web container

```bash
docker run -p 8080:8080 \
  --env-file backend/.env \
  -v "${PWD}/data:/app/data" \
  my-go-app
```

The `-v` flag mounts a local `data/` directory to persist the SQLite database across container restarts. All HTML templates and CSS are embedded into the binary, so no additional volume mounts are needed.

Navigate to `http://localhost:8080/`.

## 💻 Local Development

### Run the server

```bash
cd backend
go run ./cmd/server
```

Navigate to `http://localhost:<PORT>/`.

### Optional: Legacy JS Frontend

Configure `frontend/config.js`:
```javascript
window.APP_CONFIG = {
    API_URL: "http://localhost:8080"
};
```

Then serve it:
```bash
cd frontend
http-server ./ -p 3000 -c-1 --cors
```

## 🔌 API Endpoints

### `POST /api/share`
Creates a new encrypted secret via `multipart/form-data`.
- **Form Fields (Requires either `text` or `file`):** 
  - `text`: "string"
  - `file`: binary file
  - `expiresInMinutes`: int
  - `password`: "string"
- **Constraints**: Size < 10MB, Password 6–72 chars, Expiration ≤ 7 days (10080 min)

### `POST /api/view/:id`
Retrieves and permanently deletes a secret.
- **Body**: `{ "password": "string" }`
- **Notes**: `:id` must be a valid UUID. Secret is deleted on success.

### `GET /api/metrics`
Returns runtime memory and deletion statistics.
- **Response**: `{ "Alloc", "TotalAlloc", "Sys", "NumGC", "TimeDiffAvg", "DeletedCount" }`

## 🖥 Server-Side Rendered Routes (No JS)

| Method | Route | Description |
|--------|-------|-------------|
| `GET`  | `/` | Create-secret form |
| `POST` | `/share` | Submit form → create secret → show link |
| `GET`  | `/view/:id` | Password input form |
| `POST` | `/view/:id` | Decrypt, display, and delete secret |

No JavaScript required. Uses standard HTML forms.

## 📊 Dev Tools

### Memory Monitor
Real-time console dashboard for memory usage, GC stats, and deletion metrics:
```bash
cd backend
go run ./cmd/monitor
```

### Database Seeder
Stress-testing tool that concurrently inserts 500,000 encrypted secrets:
```bash
cd backend
go run ./cmd/seeder
```

### Debug DB
Inspect the raw database contents:
```bash
cd backend
go run ./cmd/debug_db
```

## 🔒 Security Summary

| Concern | Approach |
|---------|----------|
| Message confidentiality | AES-256-GCM encryption; plaintext never stored |
| Password security | bcrypt hashing; plaintext never stored |
| Uniqueness / replay | Random nonce per encryption; UUID per secret |
| Expiration | Hard-deleted at view time or by background scheduler |
| Abuse prevention | Rate limiting (20 req/min/IP), input validation, UUID enforcement |
