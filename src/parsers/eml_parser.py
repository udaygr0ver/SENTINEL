import email
import hashlib
import re
from datetime import datetime, timezone
from email import policy

from src.schema import ForensicArtifact


def parse_eml(file_path: str) -> list[ForensicArtifact]:
    artifacts = []
    
    try:
        with open(file_path, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
            
        subject = msg.get("Subject", "No Subject")
        sender = msg.get("From", "Unknown Sender")
        recipient = msg.get("To", "Unknown Recipient")
        date = msg.get("Date", datetime.now(timezone.utc).isoformat())
        
        # 1. Header Artifact
        auth_results = msg.get("Authentication-Results", "None")
        header_details = f"Subject: {subject}\nSender: {sender}\nRecipient: {recipient}\nAuth: {auth_results}"
        
        artifacts.append(ForensicArtifact(
            timestamp=datetime.now(timezone.utc).isoformat() + "Z",
            source_type="EML_HEADER",
            host="EMAIL_SERVER",
            user=recipient,
            details=header_details,
            ioc_detected=None
        ))
        
        # 2. Body & URLs Artifact
        body_content = ""
        body = msg.get_body(preferencelist=('plain', 'html'))
        if body:
            body_content = body.get_content()
            
            # Extract URLs
            urls = re.findall(r'(https?://[^\s]+)', body_content)
            for url in urls:
                artifacts.append(ForensicArtifact(
                    timestamp=datetime.now(timezone.utc).isoformat() + "Z",
                    source_type="EML_URL",
                    host="EMAIL_SERVER",
                    user=recipient,
                    details=f"URL Found in Body: {url}",
                    ioc_detected=url.strip('"\'>')
                ))
                
        # 3. Attachments Artifact
        for part in msg.iter_attachments():
            filename = part.get_filename()
            if filename:
                payload = part.get_payload(decode=True)
                md5_hash = hashlib.md5(payload).hexdigest() if payload else "unknown"
                artifacts.append(ForensicArtifact(
                    timestamp=datetime.now(timezone.utc).isoformat() + "Z",
                    source_type="EML_ATTACHMENT",
                    host="EMAIL_SERVER",
                    user=recipient,
                    details=f"Attachment: {filename} (MD5: {md5_hash})",
                    ioc_detected=md5_hash
                ))
                
    except Exception as e:
        print(f"Error parsing EML {file_path}: {e}")
        
    return artifacts
