# Share a Secret (Project-Simulation)

A secure, "view-once" message sharing application. Users can share encrypted text messages that are automatically deleted after being viewed or after a specified expiration time.

## 🚀 Features

- **End-to-End Encryption**: Messages are encrypted using AES-256-GCM before being stored in the database.
- **View-Once Logic**: Secrets are permanently deleted from the database immediately after the first successful retrieval.
- **Self-Destruction**: Expired secrets are automatically cleaned up by a background worker.
- **Password Protection**: Access to secrets is restricted by a user-defined password (hashed using bcrypt).
- **Rate Limiting**: Built-in protection against brute-force and spam requests.

## 🛠 Tech Stack

- **Backend**: [Go](https://go.dev/) with [Fiber](https://gofiber.io/) web framework.
- **Database**: [SQLite](https://www.sqlite.org/) managed via [GORM](https://gorm.io/).
- **Frontend**: Vanilla HTML5, CSS3, and JavaScript (ES6+).
- **Security**: `crypto/aes` for encryption, `golang.org/x/crypto/bcrypt` for password hashing.

## 📋 Prerequisites

- Go 1.25.4 or higher installed.

## ⚙️ Setup & Installation

### 1. Clone the repository
```bash
git clone https://github.com/Pestip108/Project-Simulation.git
cd Project-Simulation
```

### 2. Configure Environment Variables
The server requires a 32-byte encryption key for AES-256.
```powershell
# Windows (PowerShell)
$env:ENCRYPTION_KEY = "your-32-character-secret-key-!!"
```

### 3. Run the Backend Server
```bash
cd backend
go run cmd/server/main.go
```
The server will start on `http://localhost:4000`.

### 4. Run the Frontend
The frontend is a static web application. You can use any static file server, such as `http-server`.

```bash
cd frontend
http-server ./ -p 3000 -c-1 --cors
```

Once running, navigate to:
- **Share a secret**: `http://localhost:3000/index.html`
- **View a secret**: Accessed via the generated unique link (e.g., `http://localhost:3000/view.html?id=...`).

> [!TIP]
> The backend generates links pointing to `localhost:3000` by default. If you change the frontend port, ensure you update the link generation logic in `backend/pkg/routes/routes.go`.

## 🔌 API Endpoints

### `POST /api/share`
Creates a new encrypted secret.
- **Body**: `{ "text": "string", "expiresInMinutes": int, "password": "string" }`
- **Returns**: `{ "id": "uuid", "link": "url" }`

### `POST /api/view/:id`
Retrieves and deletes a secret.
- **Body**: `{ "password": "string" }`
- **Returns**: `{ "text": "decrypted-string" }`

## 🔒 Security Summary
This project prioritizes data privacy:
- **Zero-knowledge**: The server never stores plain-text messages or passwords.
- **Integrity**: Nonces are unique for every encryption operation.
- **Volatility**: Once viewed, the data is gone forever.
