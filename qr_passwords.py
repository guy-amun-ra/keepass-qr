import argparse
import getpass
import pykeepass
import qrcode
import re

def search_and_generate_qr(kp):
    query = input("Enter search query (q - quit): ")
    if query.lower() == "q":
        return False
    entries = search_entries(kp, query)
    if not entries:
        print(f"No entries found matching '{query}'")
        return True
    choice = choose_entry(entries)
    if not choice:
        return False
    entry = entries[choice - 1]
    qr_text = generate_qr_text(entry.password)
    print(qr_text)


def search_entries(kp, query):
    entries = kp.find_entries(title=query, regex=True)
    entries += kp.find_entries(username=query, regex=True)
    entries += kp.find_entries(notes=query, regex=True)
    return entries


def choose_entry(entries):
    for i, entry in enumerate(entries):
        print(f"{i+1}. {entry.title}")
    while True:
        try:
            choice = input("Choose an entry to generate a QR code for (or 'q' to quit): ")
            if choice.lower() == "q":
                return None
            choice = int(choice)
            if not (1 <= choice <= len(entries)):
                raise ValueError
        except ValueError:
            print("Invalid choice")
            continue
        else:
            return choice


def generate_qr_text(url):
    qr = qrcode.QRCode(version=None, box_size=2, border=4)
    qr.add_data(url)
    qr.make(fit=True)

    qr_text = ""

    for r in range(len(qr.modules)):
        for c in range(len(qr.modules[0])):
            if qr.modules[r][c]:
                qr_text += "██"
            else:
                qr_text += "  "
        qr_text += "\n"
        
    return qr_text


def main():
    parser = argparse.ArgumentParser(description="Generate QR codes for Keepass passwords")
    parser.add_argument("kdbx_path", help="Path to the KDBX file")
    args = parser.parse_args()

    password = getpass.getpass("Enter password for {}: ".format(args.kdbx_path))

    try:
        with pykeepass.PyKeePass(args.kdbx_path, password=password) as kp:
            while True:
                result = search_and_generate_qr(kp)
                if result is False:
                    break
    except pykeepass.exceptions.CredentialsError:
        print("Invalid password")

if __name__ == "__main__":
    main()
