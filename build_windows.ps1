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

# ── 3. Logo + icône .ico générée depuis le logo Heimdall ─────
$LogoSrc = "server\static\heimdall-logo.png"
if (-not (Test-Path $LogoSrc)) { $LogoSrc = "heimdall-logo.png" }
if (-not (Test-Path $LogoSrc)) {
    Write-Host "❌ Logo introuvable (server\static\heimdall-logo.png)." -ForegroundColor Red
    exit 1
}
if ($LogoSrc -ne "heimdall-logo.png") { Copy-Item $LogoSrc "heimdall-logo.png" -Force }

@'
from PIL import Image

def make_ico():
    logo = Image.open("heimdall-logo.png").convert("RGBA")
    eye = logo.crop((0, 0, logo.width, int(logo.height * 0.70)))  # l'œil, sans le texte
    sizes = [16, 32, 48, 64, 256]
    canvas = Image.new("RGBA", (256, 256), (0, 0, 0, 0))
    scale = 256 / eye.width
    eye = eye.resize((256, max(1, round(eye.height * scale))), Image.LANCZOS)
    canvas.paste(eye, (0, (256 - eye.height) // 2), eye)
    canvas.save("heimdall.ico", format="ICO", sizes=[(s, s) for s in sizes])
    print("heimdall.ico créé depuis le logo.")

make_ico()
'@ | Out-File -FilePath "heimdall_icon.py" -Encoding utf8
python heimdall_icon.py

# ── 4. Build PyInstaller ─────────────────────────────────────
Write-Host "`n🔨  Compilation de l'agent..." -ForegroundColor Cyan
pyinstaller `
    --onefile `
    --windowed `
    --name "HeimdallAgent" `
    --icon "heimdall.ico" `
    --add-data "agent.conf;." `
    --add-data "heimdall-logo.png;." `
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
