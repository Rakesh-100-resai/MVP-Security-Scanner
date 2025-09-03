# MVP Scanner (Auth + Logging)

This repo includes:
- Submission service (FastAPI) with JWT auth
- Static worker (Python) with structured logging
- Redis (queue/results) and MinIO (object storage)
- Docker Compose to run everything locally
- Host-mounted log directories under `./logs`

## Run
```bash
docker-compose up --build
```

## Get a JWT (demo)
```bash
curl -s -X POST http://localhost:8000/auth/token   -H "Content-Type: application/json"   -d '{"username":"admin","password":"changeme"}'
```
Response:
```json
{"access_token":"<JWT>","token_type":"bearer"}
```

## Upload a file
```bash
TOKEN=<paste token here>
curl -F "file=@yourfile.txt" http://localhost:8000/submit -H "Authorization: Bearer $TOKEN"
```

## Check report
```bash
curl http://localhost:8000/report/<file_id> -H "Authorization: Bearer $TOKEN"
```

## Logs
- Submission API: `./logs/submission/submission.log`
- Worker: `./logs/worker/worker.log`
