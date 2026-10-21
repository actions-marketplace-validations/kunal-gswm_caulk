FROM python:3.11-slim

WORKDIR /app

# CFG004: Copying private key and env file
COPY .env /app/.env
COPY id_rsa /root/.ssh/id_rsa

# CFG003: No non-root USER directive specified
CMD ["python", "vulnerable_app.py"]
