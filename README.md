<h2>StegTool — CLI Image Steganography (with AES-GCM Encryption)</h2>

<h3>Features:</h3>
LSB image embedding & extraction (PNG recommended)
Optional AES-GCM encryption (passphrase-protected)
Optional gzip compression
Supports hiding text or files
Simple command-line usage

<h3>Install:</h3>
pip install pillow pycryptodome


<h3>Examples:</h3>

<h4>Embed a message inside an image</h4>
python steg.py embed cover.png stego.png -m "hidden message"

<h4>Embed a file with encryption + compression</h4>
python steg.py embed cover.png stego.png --file secret.txt --compress --encrypt "mypassword"

<h4>Extract hidden data</h4>
python steg.py extract stego.png --decrypt "mypassword" --decompress
