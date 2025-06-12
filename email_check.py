""" 
This script will check the emails and determine weather the email is a potential phishing email or not.
NOTE: This is just a pre-cautionary step and in idneitfying phishing emails. You should not only rely on this alone.
 
"""

# import libraries
import imaplib
import os
import email
import tldextract
from dotenv import load_dotenv
from fuzzywuzzy import fuzz
import re

# load variables/secret keys from .env
load_dotenv(override=True)

EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_SECRET_KEY = os.getenv("EMAIL_SECRET_KEY")

# blacklist
blacklist_extenstion = [ ".exe",".bat",".cmd",".msi",".pif",".scr",".vbs",".js",".wsf",".ps1",".zip",".rar",".7z", ".tar",".gz", ".iso",".vhd",".vhdx",".dll",".cpl",".ocx",".sys",".reg",]


# function to get email contents
def get_email_info():
    
    with imaplib.IMAP4_SSL("imap.gmail.com") as imap:
        imap.login(EMAIL_ADDRESS, EMAIL_SECRET_KEY)
        imap.select("INBOX")
        _, msg_data = imap.uid("SEARCH", "X-GM-RAW", '"category:primary is:unread"')       # searching unseen email in primary folder of inbox
        #category:primary is:unread --> this is in single and then in double quotes as it has space and sever gets confused
        
        for msg in msg_data[0].split():
            _, data = imap.uid('FETCH', msg, '(BODY.PEEK[])')           # BODY.PEEK[] --> this makes sure that once fteched it is not marked as seen
            
            message = email.message_from_bytes(data[0][1])      # data is a list of byte string and we are using 0 and 1 index as content that we need is present there
            
            sender = message.get("From").split(" <")
            subject = message.get("Subject")
            date = message.get("Date")
            sender_name = sender[0].lower()
            mail = (sender[1])[:-1].lower()
            content = []
            url = []
            file_names = []
            
            for part in message.walk():
                if part.get_content_type() == "text/plain":
                    
                    # spliting each word so as to collect url later
                    individual_elements = part.as_string().split()
                    
                    for elements in individual_elements:
                        content.append(elements.lower())
                        
                # determining if email has attachment
                if part.get_content_disposition() == "attachment":
                    file_name = part.get_filename() 
                    file_names.append(file_name)   
                    
                       
            for i in content:
                if (i[:8] == "https://" or i[:7] == "http://"):
                    url.append(i)
                    
            print(f"Name: {sender_name}")
            print(f"Email: {mail}")
            print(f"Subject: {subject}")
            print(f"Date: {date}")
            print(f"URL: {url}")
            print(f"File Names: {file_names}")
            
            print("\n\n")
            
            
        potential_phishing_check(sender_name, mail, url, file_names)
            
            

# function to check if potentail phisihing
    # Check 1: Name and email mismatch
    # Check 2 : Attachements with blacklist extension and masqurated files
    # Check 3: Links Checks
    
def potential_phishing_check(sender_name, mail, url_list = None, files = None): 
    count = 0
    flag = []
    
    # Check 1: Name and email mismatch
    username = mail.split("@")[0]
    clean_username = re.sub(r'[^a-zA-Z]', '', username)      # removing non-alphanumeric characters
    name = sender_name.replace(" ","").lower()
    
    similarity_ratio = fuzz.ratio(clean_username, name)      # needs to be > than 60
    
    if (similarity_ratio < 59):
        count += 1          # this has high changes of occuring
        print("Name And Email Mismatch.\n")
        flag.append("Name And Email Mismatch.")
        
        
    # Check 2 : Attachements with blacklist extension and masqurated files
    try:
        for file in files:
            
            file_extenstion_list = file.split(".")

            if len(file_extenstion_list) > 2:
                count += 1          # masqurated file
                print("Masqurated File.\n")
                flag.append("Masqurated File.")
                
                if ("." + file_extenstion_list[-1]) in blacklist_extenstion:
                    count += 1
                    print("Masqurated File And Blacklist File Extension.\n")
                    flag.append("Masqurated File And Blacklist File Extension.") 
                
            else:
                file_extension = file_extenstion_list[1]
                
                if ("." + file_extension) in blacklist_extenstion:          # ("." + file_extension) --> as split removes the "."
                    count += 1      # malicious file
                    print("Blacklist File Extension.\n")
                    flag.append("Blacklist File Extension.")
                    
    except Exception as e:
        print(f"potential_phishing_check - Attachment Check\t{e}")
        
    # Check 3: Links Checks
    try:
        email_domain = mail.split('@')[1]
        domain = tldextract.extract(email_domain).top_domain_under_public_suffix           # this will remove all the sub-domains and only provide the actal domain
        
        for url in url_list:
            url_domain = tldextract.extract(url).top_domain_under_public_suffix
            
            if (domain != url_domain):
                count += 1
                print("Email And URL Domain Mismatch.\n")
                flag.append("Email And URL Domain Mismatch.")
                
    except Exception as e:
        print(f"potential_phishing_check - Domain Mismatch\t{e}") 
                   
    if count > 1:
        potential_phishing = "Y"
        
    else:
        potential_phishing = "N"
            

    
    
if __name__ == "__main__":
    get_email_info()
    
