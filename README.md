---
title: Touch ID Auth
emoji: 🔐
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 7860
---

# Touch ID Auth Demo

Passwordless authentication using **WebAuthn / FIDO2** with Touch ID support.

Built with FastAPI + SQLite, designed to deploy on Hugging Face Spaces.

## Deploy to Hugging Face Spaces

1. Create a new Space at [huggingface.co/new-space](https://huggingface.co/new-space)
   - Choose **Docker** as the SDK
   - Pick a name (this becomes your `RP_ID`, e.g. `your-name-touch-auth.hf.space`)

2. Push this code to your Space:
   ```bash
   git clone https://huggingface.co/spaces/YOUR_USERNAME/YOUR_SPACE_NAME
   cp -r ./* YOUR_SPACE_NAME/
   cd YOUR_SPACE_NAME
   git add . && git commit -m "Initial deploy" && git push
   ```

3. Enable **persistent storage** in your Space settings (Settings → Storage → enable it).
   This keeps the SQLite database across restarts.

4. Visit your Space URL and register with Touch ID!

## Run locally

```bash
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 7860 --reload
```

Then open http://localhost:7860

> **Note:** WebAuthn works on `localhost` for development, but requires HTTPS in production.
> HF Spaces provides HTTPS automatically.

## How it works

- **Register**: Enter a username → Touch ID creates a cryptographic key pair → public key stored in SQLite
- **Login**: Enter username → Touch ID signs a challenge → server verifies signature against stored public key
- No passwords are ever created, stored, or transmitted
- Your fingerprint data never leaves your device

## Project structure

```
├── app.py              # FastAPI backend (WebAuthn endpoints + SQLite)
├── static/index.html   # Frontend (single-page app)
├── requirements.txt    # Python dependencies
├── Dockerfile          # HF Spaces deployment
└── README.md           # This file (also HF Spaces metadata)
```
