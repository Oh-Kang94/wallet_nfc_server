from datetime import datetime
import os
from fastapi import FastAPI, HTTPException
from dotenv import load_dotenv
import logging

from applepassgenerator.client import ApplePassGeneratorClient
from applepassgenerator.models import EventTicket, ApplePass

from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Load From .env
load_dotenv()
# Setting For Use Env
CERTIFICATE_P12: str = os.environ.get('CERTIFICATE_P12')
CERTIFICATE_PEM: str = os.environ.get('CERTIFICATE_PEM')
PRIVATE_KEY_PEM: str = os.environ.get('PRIVATE_KEY_PEM')
CERTIFICATE_PASSWORD: str = os.environ.get('CERTIFICATE_PASSWORD')
WWDR_PEM: str = os.environ.get('WWDR_PEM_G4')
OUTPUT_PASS_NAME: str = "TEST.pkpass"
TEAM_IDENTIFIER = os.environ.get('TEAM_IDENTIFIER')
PASS_TYPE_IDENTIFIER = os.environ.get('PASS_TYPE_IDENTIFIER')
ORGANIZATION_NAME = os.environ.get('ORGANIZATION_NAME')

# 로고 및 아이콘 파일 경로 설정
LOGO_FILE = os.environ.get('LOGO_FILE')
ICON_FILE = os.environ.get('ICON_FILE')
BACKGROUND_FILE = os.environ.get('BACKGROUND_FILE')
THUMBNAIL_FILE = os.environ.get('THUMBNAIL_FILE')

# 매핑 정보: 환경 변수에서 읽어온 파일 경로를 지정된 이름으로 추가
file_mapping = {
    "logo.png": LOGO_FILE,
    "icon.png": ICON_FILE,
    # "background.png": BACKGROUND_FILE,
    "thumbnail.png": THUMBNAIL_FILE
}

app = FastAPI()


app.mount("/static", StaticFiles(directory="./"), name="static")


class GeneratePassResponse(BaseModel):
    message: str
    download_url: str


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get(
    "/generate_pass",
    response_model=GeneratePassResponse,
    responses={
        200: {"description": "패스 생성 성공", "model": GeneratePassResponse},
        500: {"description": "서버 에러"},
    },
)
async def generate_pass():
    logging.info("Start generating pass")
    try:
        now = datetime.now()
        datetimeToString: str = now.strftime("%Y-%m-%d %H:%M:%S")
        # 인증서 및 키 파일 추출
        extract_certificate_and_key(
            p12_path=CERTIFICATE_P12, cert_out_path=CERTIFICATE_PEM, key_out_path=PRIVATE_KEY_PEM, password=CERTIFICATE_PASSWORD)

        # 패스 정보 설정
        card_info: EventTicket = EventTicket()
        card_info.add_primary_field('Ticket', 'TicketTest', 'TicketLabel')
        card_info.add_secondary_field('TimeStamp', datetimeToString, 'DATE')

        # Apple Pass 설정
        applepassgenerator_client = ApplePassGeneratorClient(
            TEAM_IDENTIFIER, PASS_TYPE_IDENTIFIER, ORGANIZATION_NAME)
        apple_pass: ApplePass = applepassgenerator_client.get_pass(card_info)

        # 파일이 존재하는지 확인
        for file_path in [LOGO_FILE, ICON_FILE, BACKGROUND_FILE, THUMBNAIL_FILE, CERTIFICATE_PEM, WWDR_PEM, PRIVATE_KEY_PEM]:
            if not os.path.isfile(file_path):
                logging.error(f"File not found: {file_path}")
                raise HTTPException(
                    status_code=500, detail=f"File not found: {file_path}")

        # Apple Pass에 파일 추가
        for file_name, file_path in file_mapping.items():
            if not os.path.isfile(file_path):
                logging.error(f"File not found: {file_path}")
                raise HTTPException(
                    status_code=500, detail=f"File not found: {file_path}")
            try:
                with open(file_path, "rb") as file:
                    apple_pass.add_file(file_name, file)
            except Exception as e:
                logging.error(f"Failed to add file {file_name}: {e}")
                raise HTTPException(
                    status_code=500, detail=f"Failed to add file {file_name}: {e}")

        try:
            apple_pass.description = "My Project Pass"
            apple_pass.serial_number = '000000000'
            apple_pass.json_dict()
        except Exception as e:
            logging.error(f"Failed to check JSON pass: {e}")
            raise HTTPException(
                status_code=500, detail=f"Failed to create check JSON pass: {e}")

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
