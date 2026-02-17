# Share a Secret (Project-Simulation)

A secure, "view-once" message sharing application. Users can share encrypted text messages that are automatically deleted after being viewed or after a specified expiration time.

## 🚀 Features

- **End-to-End Encryption**: Messages are encrypted using AES-256-GCM before storage.
- **View-Once Logic**: Secrets are permanently deleted immediately after the first successful retrieval.
- **Self-Destruction**: Expired secrets are automatically cleaned up by a background worker (in server mode).
- **Security Hardening**:
    - Max text length: 10KB.
    - Password requirements: 6-72 characters (hashed with bcrypt).
    - Expiration limit: Max 7 days.
    - ID Validation: Strict UUID format checking.
- **Rate Limiting**: Protection against brute-force and spam requests.
- **Real-time Monitoring**: Tools to track memory usage and secret deletion metrics.

## 🛠 Tech Stack

- **Backend**: [Go](https://go.dev/) with [Fiber](https://gofiber.io/) web framework.
- **Database**: [SQLite](https://www.sqlite.org/) managed via [GORM](https://gorm.io/).
- **Frontend**: Vanilla HTML5, CSS3, and JavaScript (ES6+).
- **Security**: `crypto/aes` for encryption, `golang.org/x/crypto/bcrypt` for password hashing.

## 📋 Prerequisites

- Go 1.25.4 or higher installed.
- `http-server` (or similar) for the frontend.

## ⚙️ Configuration

### Backend (.env)
Create a `.env` file in the `backend/` directory:
```env
PORT=4000
FRONTEND_URL=http://localhost:3000
CORS_ALLOWED_ORIGINS=http://localhost:3000
ENCRYPTION_KEY=your-32-byte-secret-key-goes-here
APPDEBUG=0 //0: Real Mode, 1: Debug Mode
```

### Frontend (config.js)
Ensure `frontend/config.js` is configured with your backend URL:
```javascript
window.APP_CONFIG = {
    API_URL: "http://localhost:4000"
};
```

## ⚙️ Setup & Installation

### 1. Run the Backend Server
```bash
cd backend
go run cmd/server/main.go
```

### 2. Run the Frontend
```bash
cd frontend
http-server ./ -p 3000 -c-1 --cors
```

Once running, navigate to `http://localhost:3000/index.html`.

## 🔌 API Endpoints

### `POST /api/share`
Creates a new encrypted secret.
- **Body**: `{ "text": "string", "expiresInMinutes": int, "password": "string" }`
- **Constraints**: Text < 10KB, Password 6-72 chars, Expiration < 7 days.

### `POST /api/view/:id`
Retrieves and deletes a secret.
- **Body**: `{ "password": "string" }`
- **Validation**: `:id` must be a valid UUID.

### `GET /api/metrics`
Returns runtime memory statistics.
- **Response**: `{ "Alloc": int, "TotalAlloc": int, "Sys": int, "NumGC": int, "TimeDiffAvg": float, "DeletedCount": int }`

## 📊 Monitoring & Tools

### Memory Monitor
A real-time console dashboard to view server memory usage, garbage collection stats, and deletion metrics.
```bash
cd backend
go run cmd/monitor/main.go
```

### Database Seeder
A stress-testing tool that concurrently creates 500,000 encrypted secrets.
```bash
cd backend
go run cmd/seeder/main.go
```

## 🔒 Security Summary
This project prioritized data privacy and integrity:
- **Zero-knowledge**: Plain-text messages and passwords never touch the disk.
- **Integrity**: Each encryption uses a unique nonce.
- **Volatility**: Data is purged immediately upon viewing or expiration.
