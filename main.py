from datetime import datetime
import os
import subprocess
from fastapi import FastAPI, HTTPException
from dotenv import load_dotenv
import logging

from applepassgenerator.client import ApplePassGeneratorClient
from applepassgenerator.models import EventTicket

from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from fastapi.responses import FileResponse

# Load From .env
load_dotenv()
# Setting For Use Env
CERTIFICATE_P12: str = os.environ.get('CERTIFICATE_P12')
CERTIFICATE_PEM: str = os.environ.get('CERTIFICATE_PEM')
PRIVATE_KEY_PEM: str = os.environ.get('PRIVATE_KEY_PEM')
CERTIFICATE_PASSWORD: str = os.environ.get('CERTIFICATE_PASSWORD')
WWDR_CER: str = os.environ.get('WWDR_CER')
WWDR_PEM: str = os.environ.get('WWDR_PEM')
OUTPUT_PASS_NAME: str = "TEST.pkpass"

# 로고 및 아이콘 파일 경로 설정
LOGO_FILE = os.environ.get('LOGO_FILE')
ICON_FILE = os.environ.get('ICON_FILE')
BACKGROUND_FILE = os.environ.get('BACKGROUND_FILE')
THUMBNAIL_FILE = os.environ.get('THUMBNAIL_FILE')

app = FastAPI()


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/generate_pass")
async def generate_pass():
    logging.info("Start generating pass")
    try:
        now = datetime.now()
        datetimeToString: str = now.strftime("%Y-%m-%d %H:%M:%S")
        # 패스 정보 설정
        card_info: EventTicket = EventTicket()
        card_info.add_primary_field('Ticket', 'TicketTest', 'TicketLabel')
        card_info.add_secondary_field('TimeStamp', datetimeToString, 'DATE')

        # Apple Pass 설정
        team_identifier = "{#team_identifier}"
        pass_type_identifier = "{#pass_type_identifier}"
        organization_name = "{#organization_name}"
        applepassgenerator_client = ApplePassGeneratorClient(
            team_identifier, pass_type_identifier, organization_name)
        apple_pass = applepassgenerator_client.get_pass(card_info)

        # 인증서 및 키 파일 추출
        extract_certificate_and_key(
            p12_path=CERTIFICATE_P12, cert_out_path=CERTIFICATE_PEM, key_out_path=PRIVATE_KEY_PEM, password=CERTIFICATE_PASSWORD)

        # 파일이 존재하는지 확인
        for file_path in [LOGO_FILE, ICON_FILE, BACKGROUND_FILE, THUMBNAIL_FILE, CERTIFICATE_PEM, WWDR_PEM, PRIVATE_KEY_PEM]:
            if not os.path.isfile(file_path):
                logging.error(f"File not found: {file_path}")
                raise HTTPException(
                    status_code=500, detail=f"File not found: {file_path}")

        # Apple Pass에 파일 추가
        for file_key in [LOGO_FILE, ICON_FILE, BACKGROUND_FILE, THUMBNAIL_FILE]:
            with open(file_key, "rb") as file:
                apple_pass.add_file(os.path.basename(file_key), file)

        # 패스 파일 생성
        try:
            apple_pass.create(CERTIFICATE_PEM, PRIVATE_KEY_PEM,
                              WWDR_PEM, CERTIFICATE_PASSWORD, OUTPUT_PASS_NAME)
        except Exception as e:
            logging.error(f"Failed to create pass: {e}")
            raise HTTPException(
                status_code=500, detail=f"Failed to create pass: {e}")

        return FileResponse(OUTPUT_PASS_NAME, media_type='application/vnd.apple.pkpass', filename=OUTPUT_PASS_NAME)
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Private Method


def extract_certificate_and_key(p12_path, cert_out_path, key_out_path, password):
    try:
        with open(p12_path, "rb") as p12_file:
            p12_data = p12_file.read()
        private_key, certificate, _ = pkcs12.load_key_and_certificates(
            p12_data, password.encode(), default_backend())

        with open(cert_out_path, "wb") as pem_file:
            pem_file.write(certificate.public_bytes(
                serialization.Encoding.PEM))

        with open(key_out_path, "wb") as key_file:
            key_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    password.encode())
            ))

        logging.info("Certificate and private key extracted successfully.")
    except Exception as e:
        logging.error(f"Failed to extract certificate and key: {e}")
        raise HTTPException(
            status_code=500, detail="Failed to extract certificate and key")
