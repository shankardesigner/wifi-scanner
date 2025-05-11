.PHONY: setup run stop clean

# Create virtual environment and install dependencies
setup:
	@echo "[*] Creating virtual environment..."
	@python3 -m venv venv
	@chmod +x venv/bin/activate
	@source venv/bin/activate && pip install -r requirements.txt
	@echo "[✓] Setup complete."

# Run both main.py (Flask backend) and server.py (HTTP frontend)
run: stop
	@echo "[*] Starting backend (main.py) on port 5000..."
	@sudo venv/bin/python main.py &
	@sleep 1
	@echo "[*] Starting frontend server (server.py) on port 8080..."
	@sudo venv/bin/python server.py &
	@sleep 2
	@echo "[*] Opening browser at http://localhost:8080"
	@xdg-open http://localhost:8080 2>/dev/null || open http://localhost:8080 || true

# Kill existing main.py and server.py processes and free ports
stop:
	@echo "[*] Stopping previous instances..."
	@pkill -f "venv/bin/python main.py" || true
	@pkill -f "venv/bin/python server.py" || true
	@lsof -ti:5000 | xargs kill -9 2>/dev/null || true
	@lsof -ti:8080 | xargs kill -9 2>/dev/null || true
	@echo "[✓] All processes terminated."

# Remove venv and result files
clean: stop
	@echo "[*] Cleaning up..."
	@rm -rf venv scan-results __pycache__
	@echo "[✓] Project cleaned."
