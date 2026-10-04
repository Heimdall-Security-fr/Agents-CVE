"""Génère heimdall.ico (icône de HeimdallAgent.exe) depuis heimdall-logo.png.
Utilisé par server/Dockerfile (build CI sous Wine) et build_windows.ps1.
Usage : python make_icon.py [logo.png] [sortie.ico]"""
import sys
from PIL import Image

src = sys.argv[1] if len(sys.argv) > 1 else "heimdall-logo.png"
dst = sys.argv[2] if len(sys.argv) > 2 else "heimdall.ico"

logo = Image.open(src).convert("RGBA")
eye = logo.crop((0, 0, logo.width, int(logo.height * 0.70)))  # l'œil, sans le texte
eye = eye.crop(eye.getbbox() or (0, 0, eye.width, eye.height))  # retire les marges vides
scale = 256 / max(eye.width, eye.height)
eye = eye.resize((max(1, round(eye.width * scale)), max(1, round(eye.height * scale))), Image.LANCZOS)
canvas = Image.new("RGBA", (256, 256), (0, 0, 0, 0))
canvas.paste(eye, ((256 - eye.width) // 2, (256 - eye.height) // 2), eye)
canvas.save(dst, format="ICO", sizes=[(s, s) for s in (16, 24, 32, 48, 64, 128, 256)])
print(f"{dst} generated from {src}")  # ASCII : la console Wine n'est pas toujours UTF-8
