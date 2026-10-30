.PHONY: up down demo dev-backend dev-frontend test lint

up:            ## Build and start the app + practice lab (http://localhost:8080)
	docker compose up --build -d

down:          ## Stop everything
	docker compose down

demo:          ## Start in demo mode (replays a recorded scan, sends no packets)
	DEMO_MODE=true docker compose up --build -d backend frontend

dev-backend:   ## Run the API locally with auto-reload (needs nmap installed)
	cd backend && uvicorn app.main:app --reload

dev-frontend:  ## Run the Vite dev server (http://localhost:5173)
	cd frontend && npm run dev

test:          ## Run backend tests
	cd backend && pytest -q

lint:          ## Lint and security-scan the backend, typecheck the frontend
	cd backend && ruff check . && bandit -q -c pyproject.toml -r app
	cd frontend && npm run typecheck
