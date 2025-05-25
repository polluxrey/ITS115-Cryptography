import argparse
import os
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes


def convert_to_bmp(input_image_path, bmp_image_path):
    """Convert any image to BMP format."""
    image = Image.open(input_image_path)
    image.save(bmp_image_path, format="BMP")


def encrypt_bmp(bmp_image_path, encrypted_bmp_path, key):
    """Encrypt the pixel data of a BMP image using AES-OFB."""
    with open(bmp_image_path, "rb") as f:
        bmp_data = f.read()

    # BMP header is usually the first 54 bytes
    header = bmp_data[:54]
    pixel_data = bmp_data[54:]

    # Generate a random 16-byte IV for AES-OFB mode
    iv = get_random_bytes(AES.block_size)

    # Create AES cipher in OFB mode
    cipher = AES.new(key, AES.MODE_OFB, iv)

    # Encrypt the pixel data directly (no padding required for OFB mode)
    encrypted_pixel_data = cipher.encrypt(pixel_data)

    with open(encrypted_bmp_path, "wb") as f:
        f.write(header)  # Write unencrypted header
        f.write(iv)  # Write the IV (needed for decryption)
        f.write(encrypted_pixel_data)  # Write encrypted pixel data


def main():
    parser = argparse.ArgumentParser(
        description="Convert an image to BMP and encrypt it using AES-CBC."
    )
    parser.add_argument("input_image", help="Input image file name (e.g., image.jpg)")
    args = parser.parse_args()

    output = os.path.splitext(os.path.basename(args.input_image))[0] + "_aes-cbc.bmp"

    # Temporary file to store the converted BMP image
    temp_bmp = "temp_converted.bmp"

    print(f"Converting '{args.input_image}' to BMP format...")
    convert_to_bmp(args.input_image, temp_bmp)

    print("Encrypting BMP image using AES-CBC...")
    key = b"This is a key123"  # 16-byte key for AES-128
    encrypt_bmp(temp_bmp, output, key)

    # Remove temporary BMP file
    os.remove(temp_bmp)

    print(f"Encrypted image saved as '{output}'.")


if __name__ == "__main__":
    main()
