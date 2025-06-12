"""
This script will update the table in database table once the emails are checked.

"""

# import libraries
import os
import psycopg2
from dotenv import load_dotenv
from alert import alert_user


# load variables/secret keys from .env
load_dotenv(override=True)
DATABASE_PORT = os.getenv("DATABASE_PORT")
POSTGRES_USER = os.getenv("POSTGRES_USER")
POSTGRES_DATABASE = os.getenv("POSTGRES_DATABASE")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD")


# function to add records to table
def add_to_email_list(name, email, subject,phishing, flags=None):
    
    try:
        with psycopg2.connect(port= DATABASE_PORT, database=POSTGRES_DATABASE, user=POSTGRES_USER, password=POSTGRES_PASSWORD) as conn:
            with conn.cursor() as curr:
                
                insert_script = """
                INSERT INTO  email_list (name, sender_email, subject, "'phishing_mail(Y/N)'", recorded_on, flags) 
                VALUES (%s, %s, %s, %s, NOW(), %s)
                """
                
                curr.execute(insert_script, (name,email, subject, phishing, flags))
                print("Record Added To Email List.\n\n")
    
    except Exception as e:
        print(f"add_to_email_list\t{e}")    


# function to add phishing email address to balcklist
def add_to_blacklist(email):
    
    try:
    
        with psycopg2.connect(port= DATABASE_PORT, database=POSTGRES_DATABASE, user=POSTGRES_USER, password=POSTGRES_PASSWORD) as conn:
            with conn.cursor() as curr:
                
                select_script = "SELECT email FROM blacklist_emails WHERE email = %s"
                curr.execute(select_script, (email,))
                result = curr.fetchone()
                
                if not (result):        # if result empty insert record
                    insert_script = """
                    INSERT INTO  blacklist_emails (email) 
                    VALUES (%s)
                    """
                    
                    curr.execute(insert_script, (email,))
                    
                    print("Record Added To Blacklist Email.\n\n")
                    
    except Exception as e:
        print(f"add_to_blacklist\t{e}")
        
        

def call_database(name, email, subject, received_on ,phishing, flags=None):
    add_to_email_list(name, email, subject,phishing, flags)
    
    if phishing == "Y":
        add_to_blacklist(email)
        alert_user(name, email, subject, flags, received_on)