## 🐟 Manta – Phishing Detection Tool

##### Manta is a lightweight phishing email scanner which flags potential phishing emails.

### What It Does:
Scans the unread email via IMAP and flags the mail if it considers it to be a potential phishing email.
Phishing indicators:
- Sender dispaly name and email address name mismatch
- Email address and URLs domain mismatch
- Dangerous attachment types (.exe, .bat, .js etc)
- Double extension files


### Technologies Used:
- Python (imaplib, smtplib, fuzzywuzzy, tdlextract)
- PostgreSQL


### How to Run:
1. Install dependencies: 'pip install -r requirements.txt'
2. Run: 'python email_check.py'


### Demo
YouTube: https://www.youtube.com/watch?v=EaSxF9BRkhg 
