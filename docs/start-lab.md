# Start The AEGISAI Lab

This guide starts AEGISAI from a clean terminal session.

## 1. Start Ollama

On Windows PowerShell, expose Ollama so WSL can reach it:

```powershell
$env:OLLAMA_HOST="0.0.0.0:11434"
ollama serve
```

If PowerShell says the address is already in use, Ollama is already running.

Check installed models:

```powershell
ollama list
```

## 2. Start The Backend

Open Ubuntu WSL:

```bash
cd ~/projects/aegisai
cp .env.example .env
```

If Ollama is running on Windows and the backend is running inside WSL, find the Windows host IP:

```bash
WINDOWS_HOST=$(ip route | awk '/default/ {print $3}')
echo $WINDOWS_HOST
```

Then update `.env`:

```env
OLLAMA_BASE_URL=http://<WINDOWS_HOST>:11434
```

Start the backend:

```bash
cd ~/projects/aegisai/backend
source .venv/bin/activate
cd ..
python backend/scripts/init_db.py
uvicorn app.main:app --app-dir backend --reload
```

Health checks:

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/adapters/ollama/health
```

## 3. Start The Frontend

Open another Ubuntu WSL terminal:

```bash
cd ~/projects/aegisai/frontend
npm install
npm run dev
```

Open the dashboard:

```text
http://127.0.0.1:5173
```

## 4. Run A Basic Evaluation

```bash
curl -X POST http://127.0.0.1:8000/security-tests/suite/basic \
  -H "Content-Type: application/json" \
  -d '{"model":"qwen2.5:3b"}'
```

View scorecard:

```bash
curl "http://127.0.0.1:8000/security-tests/scorecard?model=qwen2.5:3b"
```

View release gate:

```bash
curl "http://127.0.0.1:8000/security-tests/release-gate?model=qwen2.5:3b"
```

## 5. Optional API Key

Set `AEGISAI_API_KEY` in `.env` to protect security-test endpoints:

```env
# Set this locally to a random value; do not commit the real value.
AEGISAI_API_KEY=<your-random-local-key>
```

Then send it with requests:

```bash
curl http://127.0.0.1:8000/security-tests/summary \
  -H "X-API-Key: ${AEGISAI_API_KEY}"
```
