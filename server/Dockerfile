# ── Stage 1 : Cross-compile HeimdallAgent.exe via Wine + PyInstaller ─────────
FROM cdrx/pyinstaller-windows:python3 AS win-builder

WORKDIR /src
COPY windows_agent_tray.py .

RUN pip install --quiet "requests" "pillow" "pystray>=0.19.5" "pyinstaller>=5.13"

# Vérifie que les dépendances clés sont bien importables sous Wine/Python Windows
RUN wine python -c "import pystray, PIL, PIL.Image, PIL.ImageDraw, requests; print('deps OK')"

RUN pyinstaller \
    --onefile \
    --windowed \
    --name HeimdallAgent \
    --hidden-import pystray._win32 \
    --hidden-import PIL \
    --hidden-import PIL.Image \
    --hidden-import PIL.ImageDraw \
    --hidden-import tkinter \
    --hidden-import tkinter.messagebox \
    --collect-all pystray \
    --collect-all PIL \
    windows_agent_tray.py

# ── Stage 2 : Serveur agent (embarque l'exe compilé) ──────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Dépendances Python du serveur
COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Code du serveur
COPY server/ .

# Fichiers agents (aussi accessibles via les endpoints /static/)
COPY mini_agent.py        /app/mini_agent.py
COPY windows_agent_tray.py /app/windows_agent_tray.py
COPY build_windows.ps1    /app/build_windows.ps1

# Répertoire static + exe cross-compilé depuis le stage 1
RUN mkdir -p /app/static
COPY --from=win-builder /src/dist/HeimdallAgent.exe /app/static/heimdall-agent.exe

EXPOSE 4000
CMD ["python", "main_server.py"]
