# ============================================================
# Build Heimdall Windows Agent — Génère HeimdallAgent.exe
# Exécuter en PowerShell (idéalement en admin)
# ============================================================

$ErrorActionPreference = "Stop"

Write-Host "🛡️  Heimdall Agent — Build Windows (.exe)" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# ── 1. Vérifier Python ──────────────────────────────────────
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Python introuvable. Installation via winget..." -ForegroundColor Yellow
    winget install Python.Python.3.11 --silent --accept-source-agreements --accept-package-agreements
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
}

$pyVer = python --version 2>&1
Write-Host "✅ $pyVer" -ForegroundColor Green

# ── 2. Installer les dépendances ────────────────────────────
Write-Host "`n📦  Installation des dépendances..." -ForegroundColor Cyan
pip install --quiet requests pystray pillow pyinstaller

# ── 3. Créer l'icône .ico (si inexistante) ──────────────────
if (-not (Test-Path "heimdall_icon.py")) {
    @'
from PIL import Image, ImageDraw
import os

def make_ico():
    sizes = [16, 32,48, 64, 256]
    images = []
    for sz in sizes:
        img = Image.new("RGBA", (sz, sz), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        sc = (20, 90, 200)
        pts = [(sz//2, 2), (sz-4, sz//5), (sz-4, sz//2), (sz//2, sz-2), (4, sz//2), (4, sz//5)]
        d.polygon(pts, fill=sc, outline=(180, 210, 255, 160))
        w = max(2, sz // 12)
        for x1, y1, x2, y2 in [(int(sz*.28), int(sz*.27), int(sz*.28), int(sz*.73)),
                                 (int(sz*.72), int(sz*.27), int(sz*.72), int(sz*.73)),
                                 (int(sz*.28), int(sz*.50), int(sz*.72), int(sz*.50))]:
            d.line([(x1,y1),(x2,y2)], fill="white", width=w)
        images.append(img)
    images[0].save("heimdall.ico", format="ICO", sizes=[(s,s) for s in sizes], append_images=images[1:])
    print("heimdall.ico créé.")

make_ico()
'@ | Out-File -FilePath "heimdall_icon.py" -Encoding utf8
}
python heimdall_icon.py

# ── 4. Build PyInstaller ─────────────────────────────────────
Write-Host "`n🔨  Compilation de l'agent..." -ForegroundColor Cyan
pyinstaller `
    --onefile `
    --windowed `
    --name "HeimdallAgent" `
    --icon "heimdall.ico" `
    --add-data "agent.conf;." `
    --hidden-import "pystray._win32" `
    --hidden-import "PIL._imaging" `
    windows_agent_tray.py

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Échec de la compilation." -ForegroundColor Red
    exit 1
}

Write-Host "`n✅  Compilation réussie : dist\HeimdallAgent.exe" -ForegroundColor Green

# ── 5. Copier vers le dossier static du serveur ──────────────
$StaticDir = "..\server\static"
if (Test-Path $StaticDir) {
    Copy-Item "dist\HeimdallAgent.exe" "$StaticDir\heimdall-agent.exe" -Force
    Write-Host "✅  Copié vers $StaticDir\heimdall-agent.exe" -ForegroundColor Green
    Write-Host "   → Redéployez le conteneur agent_server pour servir le .exe" -ForegroundColor Yellow
} else {
    Write-Host "ℹ️  Dossier $StaticDir introuvable. Copiez manuellement dist\HeimdallAgent.exe." -ForegroundColor Yellow
}

Write-Host "`n🎉  Build terminé !" -ForegroundColor Cyan
