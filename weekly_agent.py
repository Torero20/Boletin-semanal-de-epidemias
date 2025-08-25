"""
Weekly ECDC Agent
-----------------
Descarga el PDF más reciente desde una página de listados (por defecto, el
listado semanal del ECDC), extrae texto, genera un resumen en español y lo
envía por email (HTML + texto plano).

Características clave:
- Selección robusta del PDF más reciente (por fecha inferida/Last-Modified).
- Evita reenvíos del mismo informe con un fichero de estado `.agent_state.json`.
- Extracción de texto con pdfplumber y fallback a pdfminer.six.
- Resumen extractivo con LexRank (sumy) controlando coste.
- Traducción con cliente con fallback (googletrans opcional) o desactivable.
- Email seguro por SMTP/SSL usando credenciales de entorno/secretos.
- Logging estructurado y CLI con `--dry-run` para pruebas.

Variables de entorno (mínimas):
- SMTP_SERVER, SMTP_PORT, SENDER_EMAIL, RECEIVER_EMAIL, EMAIL_PASSWORD
Opcionales: BASE_URL, PDF_PATTERN, SUMMARY_SENTENCES, CA_FILE, LOG_LEVEL,
            NO_TRANSLATE ("1" para desactivar), AGENT_STATE_PATH

Puedes definir estas variables como **GitHub Secrets** (las sensibles) y/o
**Repository Variables** (las no sensibles) en GitHub.
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import logging
import os
import re
import ssl
import sys
from dataclasses import dataclass
from typing import List, Optional

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Carga .env si existe (para pruebas locales)
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

# PDF extracción
import pdfplumber  # type: ignore
try:
    from pdfminer.high_level import extract_text as pm_extract  # type: ignore
except Exception:
    pm_extract = None

# Sumario (LexRank)
from sumy.nlp.tokenizers import Tokenizer
from sumy.parsers.plaintext import PlaintextParser
from sumy.summarizers.lex_rank import LexRankSummarizer

# Traducción con fallback
class TranslatorClient:
    def __init__(self) -> None:
        self._gt = None
        # Permite desactivar por entorno
        self.disabled = os.getenv("NO_TRANSLATE", "0").lower() in {"1", "true", "yes"}
        try:
            from googletrans import Translator as GT  # type: ignore
            self._gt = GT()
        except Exception:
            self._gt = None

    def translate(self, text: str, dest: str = "es") -> str:
        if self.disabled:
            return text
        # Aquí podrías integrar DeepL/Google/OpenAI si defines API keys.
        if self._gt:
            try:
                return self._gt.translate(text, dest=dest).text
            except Exception:
                pass
        return text


def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": "weekly-ecdc-agent/1.0 (+contact@example.com)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
    s.mount("http://", HTTPAdapter(max_retries=retries))
    s.mount("https://", HTTPAdapter(max_retries=retries))
    return s


def _normalize(text: str) -> str:
    text = re.sub(r"-\n", "", text)  # une palabras cortadas por guión
    text = re.sub(r"\s+\n", "\n", text)
    text = re.sub(r"[ \t]{2,}", " ", text)
    return text


@dataclass
class Config:
    base_url: str = "https://www.ecdc.europa.eu/en/publications-and-data/monitoring/weekly-threats-reports"
    pdf_pattern: str = r"\.pdf$"
    summary_sentences: int = 8
    smtp_server: str = "smtp.gmail.com"
    smtp_port: int = 465
    sender_email: str = ""
    receiver_email: str = ""
    ca_file: Optional[str] = None
    state_path: str = os.getenv("AGENT_STATE_PATH", ".agent_state.json")


class WeeklyReportAgent:
    def __init__(self, config: Config, translate: bool = True, dry_run: bool = False) -> None:
        self.config = config
        self.session = make_session()
        self.translator = TranslatorClient()
        # Si el usuario quiere forzar no traducir desde CLI, respeta eso
        if not translate:
            self.translator.disabled = True
        self.dry_run = dry_run

    # ------- Utilidades de estado -------
    def _load_state(self) -> dict:
        if os.path.exists(self.config.state_path):
            try:
                with open(self.config.state_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_state(self, d: dict) -> None:
        try:
            with open(self.config.state_path, "w", encoding="utf-8") as f:
                json.dump(d, f)
        except Exception as e:
            logging.warning("No se pudo guardar el estado: %s", e)

    # ------- Selección del PDF más reciente -------
    def fetch_latest_pdf_url(self) -> Optional[str]:
        r = self.session.get(self.config.base_url, timeout=30)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")
        candidates = []
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not re.search(self.config.pdf_pattern, href, re.IGNORECASE):
                continue
            pdf_url = href if href.startswith("http") else requests.compat.urljoin(self.config.base_url, href)

            # Intenta inferir fecha del texto circundante o del enlace
            context = " ".join({a.get_text(" ", strip=True), (a.parent.get_text(" ", strip=True) if a.parent else "")})
            date_guess: Optional[dt.datetime] = None
            # Soporta YYYY-MM-DD o DD Month YYYY (EN)
            m = re.search(r"(\d{4}-\d{2}-\d{2}|\d{1,2}\s+\w+\s+\d{4})", context)
            if m:
                for fmt in ("%Y-%m-%d", "%d %B %Y"):
                    try:
                        date_guess = dt.datetime.strptime(m.group(1), fmt)
                        break
                    except ValueError:
                        continue

            # Fallback a Last-Modified
            last_mod = None
            try:
                h = self.session.head(pdf_url, timeout=15, allow_redirects=True)
                if "Last-Modified" in h.headers:
                    try:
                        last_mod = dt.datetime.strptime(h.headers["Last-Modified"], "%a, %d %b %Y %H:%M:%S %Z")
                    except Exception:
                        last_mod = None
            except requests.RequestException:
                pass

            score = date_guess or last_mod or dt.datetime.min
            candidates.append((pdf_url, score))

        if not candidates:
            return None
        candidates.sort(key=lambda x: x[1], reverse=True)
        latest_url = candidates[0][0]

        # Evita reenvíos si ya se procesó
        st = self._load_state()
        if st.get("last_pdf_url") == latest_url:
            logging.info("Último informe ya enviado; no se reenvía.")
            return None
        st["last_pdf_url"] = latest_url
        self._save_state(st)
        return latest_url

    # ------- Descarga, extracción y resumen -------
    def download_pdf(self, pdf_url: str, dest_path: str, max_mb: int = 25) -> None:
        # Verifica tamaño si es posible
        try:
            h = self.session.head(pdf_url, timeout=20, allow_redirects=True)
            clen = h.headers.get("Content-Length")
            if clen and int(clen) > max_mb * 1024 * 1024:
                raise RuntimeError(f"El PDF excede {max_mb} MB ({int(clen)/1024/1024:.1f} MB)")
        except requests.RequestException:
            pass

        with self.session.get(pdf_url, stream=True, timeout=60) as r:
            r.raise_for_status()
            with open(dest_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)

    def extract_text_from_pdf(self, pdf_path: str) -> str:
        # Primero pdfplumber
        try:
            with pdfplumber.open(pdf_path) as pdf:
                pages: List[str] = []
                for p in pdf.pages:
                    t = p.extract_text() or ""
                    pages.append(t)
            txt = "\n".join(pages)
            if len(txt.strip()) > 200:
                return _normalize(txt)
        except Exception:
            pass
        # Fallback a pdfminer.six
        if pm_extract:
            try:
                txt = pm_extract(pdf_path) or ""
                return _normalize(txt)
            except Exception:
                return ""
        return ""

    def summarize_text(self, text: str) -> str:
        if not text:
            return ""
        # Limita tamaño para coste/latencia
        snippet = text[:20000]
        parser = PlaintextParser.from_string(snippet, Tokenizer("english"))
        summarizer = LexRankSummarizer()
        sentences = summarizer(parser.document, self.config.summary_sentences)
        return " ".join(str(s) for s in sentences)

    # ------- Construcción de email -------
    @staticmethod
    def _highlight_spain(text_escaped_html: str) -> str:
        # Trabaja sobre texto ya escapado para evitar XSS
        sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", text_escaped_html) if s.strip()]
        out = []
        keys = ["España", "Spain", "Espana"]
        for s in sentences:
            if any(k.lower() in s.lower() for k in keys):
                out.append(
                    '<span style="background-color:#eaf2fa;border-left:4px solid #005ba4;padding-left:4px;">' + s + "</span>"
                )
            else:
                out.append(s)
        return " ".join(out)

    def build_html_email(self, summary_es: str, source_url: str) -> str:
        safe = html.escape(summary_es)
        highlighted = self._highlight_spain(safe)
        paragraphs = [p.strip() for p in highlighted.split("\n") if p.strip()]
        paragraph_html = "".join(f'<p style="margin:0 0 12px 0;">{p}</p>' for p in paragraphs)
        return f"""
        <html>
          <body style="font-family:Arial,Helvetica,sans-serif;line-height:1.4;background-color:#f7f7f7;padding:20px;">
            <table width="100%" cellpadding="0" cellspacing="0" style="max-width:600px;margin:auto;background-color:#ffffff;border-radius:8px;overflow:hidden;">
              <tr>
                <td style="background-color:#005ba4;color:#ffffff;padding:20px;">
                  <h1 style="margin:0;font-size:24px;">Boletín semanal de amenazas sanitarias</h1>
                  <p style="margin:0;font-size:14px;">Resumen del informe semanal</p>
                </td>
              </tr>
              <tr>
                <td style="padding:20px;">
                  {paragraph_html}
                  <p style="margin-top:20px;">Más detalles en el <a href="{html.escape(source_url)}" style="color:#005ba4;text-decoration:underline;">PDF original</a>.</p>
                </td>
              </tr>
              <tr>
                <td style="background-color:#f0f0f0;color:#666666;padding:15px;text-align:center;font-size:12px;">
                  <p style="margin:0;">© 2025.</p>
                </td>
              </tr>
            </table>
          </body>
        </html>
        """

    # ------- Email (SMTP por defecto u opción Gmail API) -------
    def send_email(self, subject: str, body: str, html_body: Optional[str] = None) -> None:
        backend = os.getenv("MAIL_BACKEND", "smtp").lower()
        sender = self.config.sender_email
        receiver = self.config.receiver_email
        if not sender or not receiver:
            raise ValueError("Debes definir SENDER_EMAIL y RECEIVER_EMAIL")

        if backend == "gmail_api":
            # --- Gmail API (OAuth2) sin app password ---
            import base64
            from email.message import EmailMessage
            try:
                from google.oauth2.credentials import Credentials  # type: ignore
                from googleapiclient.discovery import build  # type: ignore
            except Exception as e:
                raise RuntimeError("Faltan dependencias Gmail API. Añade google-auth, google-auth-oauthlib y google-api-python-client a requirements.txt") from e

            creds = Credentials(
                None,
                refresh_token=os.getenv("GMAIL_REFRESH_TOKEN"),
                client_id=os.getenv("GMAIL_CLIENT_ID"),
                client_secret=os.getenv("GMAIL_CLIENT_SECRET"),
                token_uri="https://oauth2.googleapis.com/token",
                scopes=["https://www.googleapis.com/auth/gmail.send"],
            )
            if not all([creds.refresh_token, creds.client_id, creds.client_secret]):
                raise ValueError("Faltan GMAIL_CLIENT_ID / GMAIL_CLIENT_SECRET / GMAIL_REFRESH_TOKEN")

            service = build("gmail", "v1", credentials=creds)
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = sender
            msg["To"] = receiver
            msg.set_content(body or "(Sin texto)")
            if html_body:
                msg.add_alternative(html_body, subtype="html")
            raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
            service.users().messages().send(userId="me", body={"raw": raw}).execute()
            return

        # --- SMTP (fallback con app password) ---
        import smtplib, ssl
        from email.message import EmailMessage
        password = os.getenv("EMAIL_PASSWORD")
        if not password:
            raise ValueError("EMAIL_PASSWORD no definido (SMTP)")
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = receiver
        msg.set_content(body or "(Sin texto)")
        if html_body:
            msg.add_alternative(html_body, subtype="html")
        context = ssl.create_default_context(cafile=self.config.ca_file) if self.config.ca_file else ssl.create_default_context()
        with smtplib.SMTP_SSL(self.config.smtp_server, self.config.smtp_port, context=context) as server:
            server.login(sender, password)
            server.send_message(msg)

    # ------- Pipeline ------- -------
    def run(self) -> None:
        pdf_url = self.fetch_latest_pdf_url()
        if not pdf_url:
            logging.info("No hay PDF nuevo o no se encontró ninguno.")
            return
        logging.info("PDF seleccionado: %s", pdf_url)

        import tempfile
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
        pdf_path = tmp.name
        tmp.close()
        try:
            self.download_pdf(pdf_url, pdf_path)
            text = self.extract_text_from_pdf(pdf_path)
            summary_en = self.summarize_text(text)
            summary_es = self.translator.translate(summary_en, dest="es")
            html_content = self.build_html_email(summary_es, source_url=pdf_url)
            if self.dry_run:
                logging.info("DRY-RUN activado: no se envía email.\nResumen ES (primeros 500 chars): %s", summary_es[:500])
            else:
                self.send_email("Resumen del informe semanal", summary_es, html_body=html_content)
                logging.info("Correo enviado correctamente.")
        finally:
            try:
                os.unlink(pdf_path)
            except OSError:
                pass


# ---------- CLI ----------

def build_config_from_env() -> Config:
    return Config(
        base_url=os.getenv("BASE_URL", Config.base_url),
        pdf_pattern=os.getenv("PDF_PATTERN", Config.pdf_pattern),
        summary_sentences=int(os.getenv("SUMMARY_SENTENCES", str(Config.summary_sentences))),
        smtp_server=os.getenv("SMTP_SERVER", Config.smtp_server),
        smtp_port=int(os.getenv("SMTP_PORT", str(Config.smtp_port))),
        sender_email=os.getenv("SENDER_EMAIL", ""),
        receiver_email=os.getenv("RECEIVER_EMAIL", ""),
        ca_file=os.getenv("CA_FILE") or None,
        state_path=os.getenv("AGENT_STATE_PATH", Config.state_path),
    )


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Weekly ECDC Agent")
    parser.add_argument("--dry-run", action="store_true", help="No envía email; solo imprime logs")
    parser.add_argument("--no-translate", action="store_true", help="No traducir (mantener inglés)")
    args = parser.parse_args(argv)

    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(level=getattr(logging, log_level, logging.INFO), format="%(levelname)s %(message)s")

    cfg = build_config_from_env()
    agent = WeeklyReportAgent(cfg, translate=not args.no_translate, dry_run=args.dry_run)
    agent.run()


if __name__ == "__main__":
    main()
