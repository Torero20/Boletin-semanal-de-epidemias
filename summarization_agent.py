"""
This module provides a simple agent that can download the latest PDF report from a
specified website, extract its text, generate a concise summary in Spanish, and
send the summary by email.  The script is designed to be scheduled regularly
(e.g., via cron) so that the user receives an up‑to‑date summary each week.

Before running this script you need to:

1. Install the required Python packages:
   ::
       pip install requests beautifulsoup4 pdfplumber sumy googletrans==4.0.0-rc1

2. Create an application‑specific password or use OAuth2 for your email account
   (for example, Gmail).  Never hard‑code your email password in the script; the
   script reads it from an environment variable or prompts you at runtime.

3. Update the configuration variables at the top of the script to point to the
   correct website, define the pattern for PDF links, and specify your
   sender/recipient email addresses.

The summary generation uses an extractive text summarization algorithm.  In
extractive summarization, a ranking algorithm assigns scores to sentences in
the document and selects the most important sentences to form the summary.  As
explained by Analytics Vidhya, extractive summarization "takes out the
important sentences or phrases from the original text and joins them to form a
summary"【448807350535595†L250-L255】.  The script uses the LexRank summarizer from the
`sumy` package to perform this ranking.

Text is extracted from PDFs using the `pdfplumber` library.  The Data School
blog demonstrates how to open a PDF with `pdfplumber.open()` and iterate over
its pages, calling `page.extract_text()` to collect the text【786525448396697†L45-L63】.

Email sending relies on Python's built‑in `smtplib` module, which implements
the Simple Mail Transfer Protocol (SMTP).  As Real Python notes,
`smtplib` provides a simple way to send emails with TLS or SSL encryption
【338480554383293†L138-L147】.  In the example below, the script uses `SMTP_SSL()` to
create a secure connection and `server.sendmail()` to send the message【338480554383293†L265-L286】.

"""

from __future__ import annotations

import os
import re
import ssl
import sys
import smtplib
from dataclasses import dataclass
from email.mime.text import MIMEText
from typing import List, Optional

import requests
from bs4 import BeautifulSoup
import pdfplumber  # type: ignore
from sumy.nlp.tokenizers import Tokenizer
from sumy.parsers.plaintext import PlaintextParser
from sumy.summarizers.lex_rank import LexRankSummarizer
from googletrans import Translator  # type: ignore


@dataclass
class Config:
    """Holds user‑configurable settings for the agent."""
    # Base URL of the web page listing weekly PDF reports.
    base_url: str
    # Regular expression pattern used to identify PDF links on the page.
    pdf_pattern: str = r"\.pdf$"
    # Number of sentences to include in the summary.
    summary_sentences: int = 10  # Default to a longer summary for detailed reports
    # Email settings
    smtp_server: str = "smtp.gmail.com"
    smtp_port: int = 465  # SSL port
    sender_email: str = ""
    receiver_email: str = ""
    # Optionally specify path to CA certificates (leave None to use default)
    ca_file: Optional[str] = None


class WeeklyReportAgent:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.translator = Translator()

    def fetch_latest_pdf_url(self) -> Optional[str]:
        """
        Fetch the latest PDF link from the base URL by parsing the HTML.

        Returns the full URL of the most recent PDF matching the pattern, or
        None if no PDF link is found.

        The method uses BeautifulSoup to parse the HTML page.  It searches for
        all anchor tags whose `href` attribute matches the configured
        `pdf_pattern` and returns the last occurrence, assuming the page lists
        reports chronologically.  You may need to adjust the sorting logic
        depending on the website’s structure.
        """
        response = requests.get(self.config.base_url, timeout=30)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        pdf_links: List[str] = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if re.search(self.config.pdf_pattern, href, re.IGNORECASE):
                # Resolve relative URLs
                pdf_url = href
                if not href.startswith("http"):
                    pdf_url = requests.compat.urljoin(self.config.base_url, href)
                pdf_links.append(pdf_url)
        if not pdf_links:
            return None
        # Return the last link assuming newest last
        return pdf_links[-1]

    def download_pdf(self, pdf_url: str, dest_path: str) -> None:
        """Download a PDF from the given URL to the specified destination path."""
        with requests.get(pdf_url, stream=True, timeout=60) as r:
            r.raise_for_status()
            with open(dest_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)

    def extract_text_from_pdf(self, pdf_path: str) -> str:
        """
        Extract text from a PDF using pdfplumber.

        This method opens the PDF file with `pdfplumber.open()` and iterates
        over its pages, concatenating the text extracted from each page.  This
        approach follows the example described by The Data School, where
        `page.extract_text()` is called on each page【786525448396697†L45-L63】.
        """
        text: List[str] = []
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    text.append(page_text)
        return "\n".join(text)

    def summarize_text(self, text: str) -> str:
        """
        Generate an extractive summary of the given text.

        The function uses the LexRank algorithm implemented in the `sumy`
        library.  LexRank builds a graph of sentences and ranks them based on
        their importance in the document.  The top sentences are selected
        according to `summary_sentences` in the configuration.  Because
        extractive summarization identifies and combines existing sentences
        rather than generating new ones, the resulting summary preserves the
        original meaning of the source text【448807350535595†L250-L269】.
        """
        # Create a parser and tokenizer for the text
        parser = PlaintextParser.from_string(text, Tokenizer("english"))
        summarizer = LexRankSummarizer()
        summary_sentences = summarizer(parser.document, self.config.summary_sentences)
        summary = " ".join(str(sentence) for sentence in summary_sentences)
        return summary

    def translate_to_spanish(self, text: str) -> str:
        """Translate the provided text into Spanish using googletrans."""
        try:
            translated = self.translator.translate(text, dest="es")
            return translated.text
        except Exception:
            # If translation fails, return the original text
            return text

    def highlight_spain(self, text: str) -> str:
        """
        Highlight sentences related to Spain within the provided Spanish text.

        The function splits the text into sentences using a simple period
        delimiter, then looks for keywords such as "España" or "Spain".  If a
        sentence contains any of these keywords, it is wrapped in a styled
        `<span>` element to make it stand out in the final HTML email.  This
        approach produces a modern bulletin where Spain‑specific information
        appears with a light background and a coloured border for emphasis.
        """
        sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", text) if s.strip()]
        highlighted = []
        keywords = ["España", "Spain", "Espana"]
        for sentence in sentences:
            if any(k.lower() in sentence.lower() for k in keywords):
                # Wrap Spain-related sentences in a coloured span.  We avoid
                # line breaks inside the string literal to ensure valid syntax.
                wrapped = (
                    '<span style="background-color:#eaf2fa; border-left:4px solid #005ba4; padding-left:4px;">'
                    + sentence +
                    '</span>'
                )
                highlighted.append(wrapped)
            else:
                highlighted.append(sentence)
        return " ".join(highlighted)

    def build_html_email(self, summary_es: str) -> str:
        """
        Construct an HTML bulletin from the Spanish summary.

        This helper builds a simple, responsive newsletter with a coloured header,
        clear section titles and highlighted Spain-specific sentences.  It uses
        inline CSS for maximum compatibility with email clients.  The final
        content returned by this method can be passed directly to
        ``send_email``.
        """
        # First highlight Spain-related sentences
        highlighted_summary = self.highlight_spain(summary_es)
        # Break the summary into paragraphs for readability
        paragraphs = highlighted_summary.split("\n")
        paragraph_html = "".join(
            f"<p style=\"margin:0 0 12px 0;\">{p.strip()}</p>" for p in paragraphs if p.strip()
        )
        html = f"""
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
                  <p style="margin-top:20px;">
                    Para más información consulta el <a href="{self.config.base_url}" style="color:#005ba4;text-decoration:underline;">informe completo del ECDC</a>.
                  </p>
                </td>
              </tr>
              <tr>
                <td style="background-color:#f0f0f0;color:#666666;padding:15px;text-align:center;font-size:12px;">
                  <p style="margin:0;">Has recibido este boletín porque estás suscrito a las actualizaciones semanales.</p>
                  <p style="margin:0;">© 2025. Todos los derechos reservados.</p>
                </td>
              </tr>
            </table>
          </body>
        </html>
        """
        return html

    def send_email(self, subject: str, body: str, html_body: Optional[str] = None) -> None:
        """
        Send an email using the configured SMTP server.

        This version constructs a multipart message with both plain‑text and
        optional HTML versions.  It prompts for the sender’s password if not
        provided via the `EMAIL_PASSWORD` environment variable.  The message
        is sent using an SSL connection (`SMTP_SSL`) as recommended for
        secure transmission【338480554383293†L265-L286】.  You can add attachments
        by extending this function and attaching files to the `EmailMessage`.
        """
        sender = self.config.sender_email
        receiver = self.config.receiver_email
        if not sender or not receiver:
            raise ValueError("Sender and receiver email addresses must be set in the configuration.")
        # Acquire password securely
        password = os.getenv("EMAIL_PASSWORD")
        if not password:
            import getpass
            password = getpass.getpass(f"Introduce la contraseña de {sender}: ")
        # Build multipart email
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = receiver
        # Set plain‑text content
        msg.set_content(body)
        # Add HTML alternative if provided
        if html_body:
            msg.add_alternative(html_body, subtype="html")
        # Create SSL context
        context = ssl.create_default_context(cafile=self.config.ca_file) if self.config.ca_file else ssl.create_default_context()
        with smtplib.SMTP_SSL(self.config.smtp_server, self.config.smtp_port, context=context) as server:
            server.login(sender, password)
            server.send_message(msg)

    def run(self) -> None:
        """
        Execute the full workflow: find the latest PDF, download it, extract
        text, summarize, translate to Spanish, and email the summary.

        If no PDF link is found on the page, the function prints a message and
        exits without sending an email.
        """
        pdf_url = self.fetch_latest_pdf_url()
        if not pdf_url:
            print("No PDF link found on the page.")
            return
        print(f"Found PDF: {pdf_url}")
        # Download PDF to a temporary file
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
            self.download_pdf(pdf_url, tmp.name)
            pdf_path = tmp.name
        # Extract and summarize text
        text = self.extract_text_from_pdf(pdf_path)
        # Generate an English extractive summary
        summary_en = self.summarize_text(text)
        # Translate the summary to Spanish
        summary_es = self.translate_to_spanish(summary_en)
        # Build HTML bulletin using the translated summary
        html_content = self.build_html_email(summary_es)
        # Compose subject and send both plain and HTML versions
        subject = "Resumen del informe semanal"
        self.send_email(subject, summary_es, html_body=html_content)
        print("Summary email sent successfully.")


def main() -> None:
    # Define configuration.  The user must update these values.
    config = Config(
        # URL of the weekly threats report page.  Replace it with the page
        # corresponding to the current week; for automatic updates use the
        # general listing page of the CDTR series.
        base_url="base_url="https://www.ecdc.europa.eu/en/publications-and-data/monitoring/weekly-threats-reports",
        # This setting is also configurable via Config.summary_sentences but
        # defaults to a longer summary in the dataclass.
        summary_sentences=10,
        smtp_server="smtp.gmail.com",
        smtp_port=465,
        # Replace the following addresses with your sender and recipient emails.
        sender_email="agentia70@gmail.com",
        receiver_email="contra1270@gmail.com",
    )
    agent = WeeklyReportAgent(config)
    agent.run()


if __name__ == "__main__":
    main()
