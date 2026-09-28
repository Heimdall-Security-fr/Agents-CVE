# ── Stage 1 : Cross-compile HeimdallAgent.exe via Wine + PyInstaller ─────────
FROM cdrx/pyinstaller-windows:python3 AS win-builder

WORKDIR /src
COPY windows_agent_tray.py .
COPY server/static/heimdall-logo.png .
COPY VERSION .

# Version de l'agent : AGENT_VERSION (build-arg de la CI, ex. 1.0.57) si valide, sinon
# le contenu de VERSION. Elle est écrite dans l'exe : c'est ce qui permet aux agents
# déjà installés de détecter qu'une version plus récente est disponible.
ARG AGENT_VERSION=""
RUN V="$AGENT_VERSION"; \
    printf '%s' "$V" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || V="$(tr -d ' \r\n' < VERSION)"; \
    sed -i "s/^AGENT_VERSION = \"[^\"]*\"/AGENT_VERSION = \"${V}\"/" windows_agent_tray.py; \
    grep -q "^AGENT_VERSION = \"${V}\"" windows_agent_tray.py && echo "Agent Windows version ${V}"

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
    --add-data "heimdall-logo.png;." \
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

# Même version partout : agents servis (/static/mini_agent.py…) ET version publiée par
# le serveur (/api/agent/version). Sans cela, un agent mis à jour verrait toujours une
# version « plus récente » et se mettrait à jour en boucle.
COPY VERSION /tmp/VERSION
ARG AGENT_VERSION=""
RUN V="$AGENT_VERSION"; \
    printf '%s' "$V" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || V="$(tr -d ' \r\n' < /tmp/VERSION)"; \
    sed -i "s/^AGENT_VERSION = \"[^\"]*\"/AGENT_VERSION = \"${V}\"/" /app/mini_agent.py /app/windows_agent_tray.py; \
    grep -q "^AGENT_VERSION = \"${V}\"" /app/mini_agent.py && \
    echo "${V}" > /app/.agent_version && rm /tmp/VERSION && echo "Serveur agent version ${V}"

# Répertoire static + exe cross-compilé depuis le stage 1
RUN mkdir -p /app/static
COPY --from=win-builder /src/dist/HeimdallAgent.exe /app/static/heimdall-agent.exe

EXPOSE 4000
CMD ["python", "main_server.py"]
