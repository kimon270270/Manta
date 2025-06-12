"""
This script will check the database if there are any potential phishing emails and if there are such emails send alter email.
  
"""

# import libraries
import os
import smtplib
from dotenv import load_dotenv


# load variables/secret keys from .env
load_dotenv(override=True)
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_SECRET_KEY = os.getenv("EMAIL_SECRET_KEY")


# function to alert user
def alert_user(name, email, subject, flags, received_on):
    
    text = f"""Subject: Potential Phishing Mail Alert!!!\n\n
    Name: {name}\n
    Email: {email}\n
    Email_Subject: {subject}\n
    Received On: {received_on}\n
    Flags: {flags}\n
    """
    
    with smtplib.SMTP("smtp.gmail.com", "587") as server:
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_SECRET_KEY)
        server.sendmail(from_addr=EMAIL_ADDRESS, to_addrs=EMAIL_ADDRESS, msg=text)
        
    print("Alert Sent!!!\n\n")