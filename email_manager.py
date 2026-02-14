import smtplib, os, uuid, secrets, hashlib
from email.message import EmailMessage
from email.utils import formataddr
from db import pool
from datetime import datetime, timedelta, timezone

BASE_URL = os.environ["BASE_URL"] # so we can switch urls between environments easily
# it really doesn't have to be a class but I like it, oh well
class EmailClient:
    def __init__(self):
        self.sender_email = "rpsnotifcation@gmail.com" # note that there is no "i" in notification
        self.sender_password = os.environ["EMAIL_PASSWORD"]

    def send_email(self, recipient_email: str, email_subject: str, email_body: str, html_body: str | None = None):
        msg = EmailMessage()
        msg["From"] = formataddr(("RPS Notifications", self.sender_email))
        msg["To"] = recipient_email
        msg["Subject"] = email_subject
        msg.set_content(email_body)  

        if html_body:
            msg.add_alternative(html_body, subtype="html")

        with smtplib.SMTP("smtp.gmail.com", 587, timeout=30) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(self.sender_email, self.sender_password)
            server.send_message(msg)

    def send_verification(self, recipient_email: str, verification_url: str):
        subject = "Verify your email"
        text_body = (
            "Thanks for making an account for https://rps9.net !\n\n"
            f"Please verify your email by opening this link:\n{verification_url}\n\n"
            "If you didn't make an account, please ignore this email."
        )

        # define palette
        bg = "#111827"
        card = "#1F2937"
        text = "#E5E7EB"
        secondary = "#9CA3AF"
        accent = "#3B82F6"
        preheader = "Verify your email"

        html_body = f"""\
            <!doctype html>
            <html>
            <head>
                <meta name="viewport" content="width=device-width,initial-scale=1"/>
                <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
                <title>{subject}</title>
                <style>.preheader{{display:none!important;visibility:hidden;opacity:0;height:0;width:0;overflow:hidden;color:transparent}}</style>
            </head>
            <body style="margin:0;padding:0;background:{bg};">
                <span class="preheader">{preheader}</span>
                <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="background:{bg};padding:24px 12px;">
                <tr>
                    <td align="center">
                    <table role="presentation" cellpadding="0" cellspacing="0" width="600"
                            style="max-width:600px;width:100%;background:{card};border-radius:14px;box-shadow:0 6px 28px rgba(0,0,0,0.35);">
                        <tr>
                        <td style="padding:28px 28px 24px 28px;">
                            <h1 style="margin:0 0 12px 0;color:{text};font-size:24px;line-height:1.2;font-weight:800;">Verify your email</h1>
                            <p style="margin:0 0 12px 0;color:{text};line-height:1.55;font-size:16px;">Thanks for making an account for https://rps9.net !</p>
                            <p style="margin:0 0 12px 0;color:{text};line-height:1.55;font-size:16px;">Please confirm your email by clicking the button below.</p>
                            <div style="margin-top:20px;">
                            <a href="{verification_url}"
                                style="display:inline-block;padding:12px 20px;background:{accent};color:#FFFFFF;
                                        text-decoration:none;border-radius:10px;font-weight:700;font-size:16px;">
                                Verify email
                            </a>
                            </div>
                            <p style="margin:24px 0 0 0;color:{secondary};font-size:13px;line-height:1.55;">
                            If you didn't create an account, you can ignore this email.
                            </p>
                        </td>
                        </tr>
                    </table>
                    </td>
                </tr>
                </table>
            </body>
            </html>
        """
        self.send_email(recipient_email, subject, text_body, html_body)


def issue_email_verification_link(user_id: int) -> str:
    token_id = str(uuid.uuid4())
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)

    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "DELETE FROM email_verifications WHERE user_id = %s AND used_at IS NULL",
            (user_id,)
        )
        cur.execute(
            "INSERT INTO email_verifications (id, user_id, token_hash, expires_at) VALUES (%s, %s, %s, %s)",
            (token_id, user_id, token_hash, expires_at)
        )

    base = f"{BASE_URL}/api/auth/verify-email"
    return f"{base}?token_id={token_id}&token={raw_token}"

def main():
    notification_email = EmailClient()
    notification_email.send_verification("ryans6892@gmail.com", "https://rps9.net")

if __name__ == "__main__":
    main()
