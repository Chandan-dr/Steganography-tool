StegTool — CLI Image Steganography (with AES-GCM Encryption)

Features:
LSB image embedding & extraction (PNG recommended)
Optional AES-GCM encryption (passphrase-protected)
Optional gzip compression
Supports hiding text or files
Simple command-line usage

Install:
pip install pillow pycryptodome


Examples

# Embed a message inside an image
python steg.py embed cover.png stego.png -m "hidden message"

# Embed a file with encryption + compression
python steg.py embed cover.png stego.png --file secret.txt --compress --encrypt "mypassword"

# Extract hidden data
python steg.py extract stego.png --decrypt "mypassword" --decompress
