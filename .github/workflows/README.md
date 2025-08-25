# Weekly ECDC Agent

Agente que descarga el último PDF del ECDC (Weekly Threats Reports), extrae texto, hace un resumen **en español** y lo envía por correo.

## 1) Requisitos
- Cuenta SMTP (por ejemplo, **Gmail con contraseña de aplicación** y 2FA activado).
- Un repositorio en GitHub con GitHub Actions habilitado.

## 2) Archivos
Incluye en la raíz del repo:
- `weekly_agent.py`
- `requirements.txt`
- `.github/workflows/weekly-report.yml`

## 3) Configuración en GitHub
Ve a **Settings → Secrets and variables → Actions** y crea:

### Secrets (sensibles)
- `SMTP_SERVER` → p.ej. `smtp.gmail.com`
- `SMTP_PORT` → `465`
- `SENDER_EMAIL` → tu email remitente
- `RECEIVER_EMAIL` → email destinatario
- `EMAIL_PASSWORD` → **contraseña de aplicación** (no la normal)

### Variables (opcionales)
- `BASE_URL` → URL del listado; por defecto usa la del ECDC Weekly Threats
- `PDF_PATTERN` → regex para PDF (por defecto `\.pdf$`)
- `SUMMARY_SENTENCES` → número de frases del resumen (p.ej. `8`)
- `CA_FILE` → ruta a bundle CA (normalmente vacío)

> **Gmail**: crea una *App Password* en tu cuenta con 2FA (Google Account → Security → 2‑Step Verification → App passwords) y úsala en `EMAIL_PASSWORD`.

## 4) Programación
El workflow viene con un cron: **lunes 08:00 UTC** (10:00 España en verano). Puedes cambiarlo en `.github/workflows/weekly-report.yml`.

## 5) Ejecución manual
En la pestaña **Actions** de tu repo, elige “Enviar resumen semanal del ECDC” y pulsa **Run workflow**.

## 6) Prueba local (opcional)
1. Crea un `.env` con:
   ```env
   SMTP_SERVER=smtp.gmail.com
   SMTP_PORT=465
   SENDER_EMAIL=tu_correo@gmail.com
   RECEIVER_EMAIL=destino@dominio.com
   EMAIL_PASSWORD=tu_app_password
   LOG_LEVEL=INFO
