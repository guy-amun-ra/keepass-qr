# Readme

## Build Docker
```bash
docker build -t qr_passwords .
```
## Run Docker
```bash
docker run -it --rm -v $PWD/mypassowrd.kdbx:/app/your.kdbx qr_passwords /app/your.kdbx
```
## Run command
```bash
./pwqr.sh ./mypassowrd.kdbx
```
