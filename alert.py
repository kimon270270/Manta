"""
This script will check the database if there are any potential phishing emails and if there are such emails send alter email.
  
"""

# import libraries
import os
import smtplib
import psycopg2
from dotenv import load_dotenv


# load variables/secret keys from .env
load_dotenv(override=True)



# function get info from database



# function to verify whether the email is potential phishing
    # if true send alert

