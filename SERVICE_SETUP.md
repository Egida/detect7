# Detect7 Public Service (UI + API)

This repository now includes a public-facing service scaffold:

- `backend/`: FastAPI service with user auth, domain onboarding, verification, and dashboard APIs.
- `frontend/`: Vue 3 + Bootstrap app with landing page and user panel.

## Backend (FastAPI)

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
set DATABASE_URL=mysql+pymysql://root:root@127.0.0.1:3306/detect7_service
uvicorn app.main:app --reload --port 8000
```

## Frontend (Vue)

```bash
cd frontend
npm install
npm run dev
```

Optional env:

- `frontend/.env`:
  - `VITE_API_BASE_URL=http://localhost:8001`

- Backend env:
  - `DATABASE_URL=mysql+pymysql://root:YOUR_PASSWORD@127.0.0.1:3306/detect7_service`

## Docker (separate SaaS stack, bind-mount dev mode)

The new UI/API services are dockerized in a dedicated compose file so they do not conflict with the original Detect7 stack.
This compose runs in bind-mount mode (no image rebuild required for code changes):

- `docker-compose.saas.yml` -> only `frontend` + `backend`
- `docker-compose.yml` -> existing Detect7 detection stack

Run SaaS stack:

```bash
set DATABASE_URL=mysql+pymysql://root:YOUR_PASSWORD@host.docker.internal:3306/detect7_service
docker compose -f docker-compose.saas.yml up -d
```

Open:

- Frontend: `http://localhost:5174`
- Backend API: `http://localhost:8001`

Notes:

- Backend runs `uvicorn --reload` inside container and watches mounted `./backend`.
- Frontend runs Vite dev server inside container and watches mounted `./frontend`.
- After source/config edits, refresh browser; no `docker build` required.

MariaDB connection used by Dockerized backend (from host machine):

- `mysql+pymysql://root:YOUR_PASSWORD@host.docker.internal:3306/detect7_service`

Create DB once in MariaDB if needed:

```sql
CREATE DATABASE detect7_service CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

Stop SaaS stack:

```bash
docker compose -f docker-compose.saas.yml down
```

## Implemented product features

- Public landing page using non-sensitive Detect7 information.
- User registration and login (JWT bearer auth).
- Domain management:
  - Add multiple domains
  - Delete domains
  - Domain ownership verification via TXT file in public root
- Log forwarding guide with Nginx snippets.
- Dashboard page with charts and summary cards.
