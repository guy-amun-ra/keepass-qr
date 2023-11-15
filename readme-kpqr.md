# keepass qr
## requirements:
```bash
pip install pykeepass qrcode keyring schedule cryptography cachetools subprocess
sudo apt install at
```
## how to run:
```bash
python script.py -k /path/to/keepass.kdbx -s EntryName
python script.py -k /path/to/keepass.kdbx -s EntryName -n 2
```

