# ULPF Air-Gapped Deployment Runbook

This guide covers deploying ULPF on completely disconnected / isolated networks (e.g. defense SCIF, internal enterprise networks) with **zero internet connectivity**.

---

### Option 1: Native Python Air-Gapped Setup

1. **Transfer the project folder** to the offline target workstation via approved removable media.
2. **Create virtual environment & install from offline wheels**:
   ```bash
   cd ULPF
   python3 -m venv .venv
   source .venv/bin/activate
   pip install --no-index --find-links=offline_packages -r requirements.txt
   ```
3. **Start the server**:
   ```bash
   PYTHONPATH=backend python backend/app/main.py datasets/sample/
   PYTHONPATH=backend uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
   ```
4. Access the web dashboard locally at: `http://127.0.0.1:8000`

---

### Option 2: Air-Gapped Container Image Transfer (Docker)

1. **On the build machine (connected to local docker engine)**:
   ```bash
   docker build -t ulpf:latest .
   docker save ulpf:latest -o ulpf_airgapped.tar
   ```
2. **Transfer `ulpf_airgapped.tar`** to the isolated target machine.
3. **On the target machine**:
   ```bash
   docker load -i ulpf_airgapped.tar
   docker run -d \
     -p 8000:8000 \
     -v $(pwd)/data:/app/data \
     -v $(pwd)/exports:/app/exports \
     --name ulpf_container \
     ulpf:latest
   ```
4. Access the containerized web UI at: `http://localhost:8000`
