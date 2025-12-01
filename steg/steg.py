#!/usr/bin/env python3
# steg.py — robust LSB steganography with optional AES-GCM encryption

import argparse
import gzip
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

MAGIC = b"STEGv1"  # 6 bytes to identify our payload


# ---------- crypto helpers ----------

def derive_key(password: str, salt: bytes, key_len: int = 32) -> bytes:
    """
    Derive a symmetric key from a password using scrypt.
    Signature compatible with your PyCryptodome version:
    scrypt(password, salt, key_len, N, r, p)
    """
    return scrypt(password.encode(), salt, key_len, 2**14, 8, 1)


def encrypt_aes_gcm(plaintext: bytes, password: str) -> bytes:
    """
    Encrypt plaintext using AES-GCM.
    Payload layout (after the mode byte 'E'):
        salt(16) + nonce(12) + tag(16) + ciphertext
    """
    salt = get_random_bytes(16)
    key = derive_key(password, salt)
    nonce = get_random_bytes(12)  # standard GCM nonce length
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return salt + nonce + tag + ciphertext


def decrypt_aes_gcm(blob: bytes, password: str) -> bytes:
    """
    Decrypt AES-GCM payload.
    Blob layout:
        salt(16) + nonce(12) + tag(16) + ciphertext
    """
    if len(blob) < 16 + 12 + 16:
        raise ValueError("Encrypted payload too short or corrupted.")
    salt = blob[:16]
    nonce = blob[16:28]
    tag = blob[28:44]
    ciphertext = blob[44:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


# ---------- bit helpers ----------

def bytes_to_bits(b: bytes):
    for byte in b:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1


def bits_to_bytes(bits):
    out = bytearray()
    cur = 0
    count = 0
    for bit in bits:
        cur = (cur << 1) | bit
        count += 1
        if count == 8:
            out.append(cur)
            cur = 0
            count = 0
    return bytes(out)


# ---------- header helpers ----------

def make_header(payload_len: int) -> bytes:
    """
    Header: MAGIC (6 bytes) + 4-byte big-endian payload length
    """
    return MAGIC + payload_len.to_bytes(4, "big")


def parse_header(header_bytes: bytes) -> int:
    """
    Parse header and return payload length.
    """
    if len(header_bytes) < len(MAGIC) + 4:
        raise ValueError("Header too short.")
    if not header_bytes.startswith(MAGIC):
        raise ValueError("No STEG header found in image.")
    length_bytes = header_bytes[len(MAGIC):len(MAGIC) + 4]
    return int.from_bytes(length_bytes, "big")


# ---------- embedding & extraction ----------

def embed(cover_path: str, out_path: str, payload: bytes, bits_per_channel: int = 1):
    """
    Embed payload bytes into the cover image using LSB substitution.
    """
    img = Image.open(cover_path)
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGBA")

    pixels = list(img.getdata())
    channels = 4 if img.mode == "RGBA" else 3
    width, height = img.size

    header = make_header(len(payload))
    full = header + payload
    total_bits = len(full) * 8

    capacity_bits = width * height * channels * bits_per_channel
    if total_bits > capacity_bits:
        raise ValueError(
            f"Payload too large. Need {total_bits} bits but capacity is {capacity_bits} bits."
        )

    bit_iter = bytes_to_bits(full)
    new_pixels = []
    done = False

    for idx, px in enumerate(pixels):
        comps = list(px)
        for c in range(channels):
            for b in range(bits_per_channel):
                try:
                    bit = next(bit_iter)
                except StopIteration:
                    done = True
                    break
                # embed bit in the b-th LSB of this channel
                comps[c] = (comps[c] & ~(1 << b)) | (bit << b)
            if done:
                break
        new_pixels.append(tuple(comps))
        if done:
            # Copy remaining pixels unchanged
            new_pixels.extend(pixels[idx + 1:])
            break

    img_out = Image.new(img.mode, img.size)
    img_out.putdata(new_pixels)
    img_out.save(out_path, "PNG")
    print(f"Saved stego image to {out_path}")


def extract(stego_path: str, bits_per_channel: int = 1) -> bytes:
    """
    Extract payload bytes from the stego image.
    """
    img = Image.open(stego_path)
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGBA")

    pixels = list(img.getdata())
    channels = 4 if img.mode == "RGBA" else 3

    def bit_generator():
        for px in pixels:
            for c in range(channels):
                for b in range(bits_per_channel):
                    yield (px[c] >> b) & 1

    bits = bit_generator()

    # 1) Read header
    header_len_bytes = len(MAGIC) + 4
    header_bits_count = header_len_bytes * 8
    header_bytes = bits_to_bytes(next(bits) for _ in range(header_bits_count))
    payload_len = parse_header(header_bytes)

    # 2) Read payload of known length
    payload_bits_count = payload_len * 8
    payload_bytes = bits_to_bytes(next(bits) for _ in range(payload_bits_count))
    return payload_bytes


# ---------- CLI ----------

def main():
    parser = argparse.ArgumentParser(description="Simple image steganography tool")
    sub = parser.add_subparsers(dest="cmd")

    # Embed command
    e = sub.add_parser("embed", help="Embed message/file into image")
    e.add_argument("cover", help="Cover image path (PNG recommended)")
    e.add_argument("out", help="Output stego image path")
    e.add_argument("-m", "--message", help="Message to hide (text). If omitted, reads from stdin", default=None)
    e.add_argument("--file", help="File to hide", default=None)
    e.add_argument("--compress", action="store_true", help="Compress data before embedding")
    e.add_argument("--encrypt", help="Passphrase for AES-GCM encryption", default=None)
    e.add_argument("--bits", type=int, default=1, help="Bits per channel (1 recommended)")

    # Extract command
    x = sub.add_parser("extract", help="Extract hidden data from image")
    x.add_argument("stego", help="Stego image path")
    x.add_argument("--decrypt", help="Passphrase to decrypt", default=None)
    x.add_argument("--decompress", action="store_true", help="Decompress after extraction")
    x.add_argument("--bits", type=int, default=1, help="Bits per channel used during embed")

    args = parser.parse_args()

    if args.cmd == "embed":
        # Read input data
        if args.file:
            with open(args.file, "rb") as f:
                data = f.read()
        else:
            if args.message is None:
                data = input("Enter message: ").encode()
            else:
                data = args.message.encode()

        # Optional compression
        if args.compress:
            data = gzip.compress(data)

        # Optional encryption
        if args.encrypt:
            enc_blob = encrypt_aes_gcm(data, args.encrypt)
            # prefix with 'E' to indicate encrypted
            payload = b"E" + enc_blob
        else:
            # prefix with 'P' to indicate plaintext
            payload = b"P" + data

        embed(args.cover, args.out, payload, bits_per_channel=args.bits)

    elif args.cmd == "extract":
        payload = extract(args.stego, bits_per_channel=args.bits)
        if not payload:
            print("No payload found or image corrupted.")
            return

        mode = payload[0:1]
        body = payload[1:]

        # Handle encrypted or plain
        if mode == b"E":
            if not args.decrypt:
                print("Payload is encrypted. Provide --decrypt passphrase.")
                return
            try:
                pt = decrypt_aes_gcm(body, args.decrypt)
            except Exception as e:
                print("Decryption failed:", e)
                return
        elif mode == b"P":
            pt = body
        else:
            print("Unknown payload mode. Data may be corrupted.")
            return

        # Optional decompression
        if args.decompress:
            try:
                pt = gzip.decompress(pt)
            except Exception as e:
                print("Decompression failed:", e)
                # fall through and print raw

        # Try to print as text; if binary, write to file
        try:
            print(pt.decode())
        except UnicodeDecodeError:
            with open("extracted.bin", "wb") as f:
                f.write(pt)
            print("Binary payload written to extracted.bin")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
