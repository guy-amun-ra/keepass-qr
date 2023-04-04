FROM python:3.8-slim-buster

# Install necessary packages
RUN apt-get update && apt-get install -y keepass2 qrencode

RUN pip3 install qrcode pykeepass

# Copy the Python script into the container
COPY qr_passwords.py .

# Set the entrypoint for the container
ENTRYPOINT ["python", "qr_passwords.py"]