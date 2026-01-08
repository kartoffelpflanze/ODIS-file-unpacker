import os
import argparse
import zipfile
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# The key for the AES algorithm is stored as an array of integers in some plugin, here it's stored in hex.
AES_KEY = bytearray.fromhex('47 61 91 D4 DF F8 5C 6E 73 2D 26 59 A2 CD 48 BE E7 3C B9 D1 AA 92 FA C9 29 19 E8 A0 72 A2 2C 32')

# Files starting with these strings (inside .jar archives) will go through decryption.
PROTECTED_PACKAGES = [
    'de/volkswagen/odis',
    'de/volkswagen/smardlang',
    'de/vw/vaudes/security',
    'de/volkswagen/ecf'
]


# Check if a file needs to be decrypted
def is_protected(filename):
    for prefix in PROTECTED_PACKAGES:
        if filename.startswith(prefix):
            return True
    return False

# AES decryption
def decrypt_data(data):
    try:
        cipher = AES.new(AES_KEY, AES.MODE_ECB)
        decrypted = cipher.decrypt(data)
        return unpad(decrypted, AES.block_size)
    except Exception as e:
        return data

# Unpack every file in the archive
def process_jar(jar_path, output_root):
    try:
        with zipfile.ZipFile(jar_path, 'r') as jar:
            # Check if this archive contains any protected files.
            contains_encrypted = False
            for name in jar.namelist():
                if is_protected(name):
                    contains_encrypted = True
                    break
            
            if not contains_encrypted:
                return

            print(f'[+] Unpacking: {os.path.basename(jar_path)}')

            # Create the output directory (named the same as the archive, without extension).
            jar_name = os.path.splitext(os.path.basename(jar_path))[0]
            jar_output_dir = os.path.join(output_root, jar_name)
            os.makedirs(jar_output_dir, exist_ok=True)

            # Decrypt each file.
            for file_info in jar.infolist():
                name = file_info.filename
                
                # Skip directories.
                if name.endswith('/'):
                    continue

                # Only decrypt the file's bytes if it is a .class file and its name starts with one of those strings.
                file_bytes = jar.read(file_info)
                if is_protected(name) and name.endswith('.class'):
                    file_bytes = decrypt_data(file_bytes)

                output_path = os.path.join(jar_output_dir, name)
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                
                with open(output_path, 'wb') as f_out:
                    f_out.write(file_bytes)

    except Exception as e:
        print(f'[-] Error processing {os.path.basename(jar_path)}: {e}')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input_folder')
    parser.add_argument('output_folder')
    args = parser.parse_args()

    input_dir = args.input_folder
    output_dir = args.output_folder

    if not os.path.isdir(input_dir):
        print('Error: Input path is not a directory.')
        return

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Collect all .jar files in the input directory.
    jar_files = [
        os.path.join(input_dir, f) 
        for f in os.listdir(input_dir) 
        if f.lower().endswith('.jar') and os.path.isfile(os.path.join(input_dir, f))
    ]

    if not jar_files:
        print('No .jar files found in input directory.')
        return

    for jar_file in jar_files:
        process_jar(jar_file, output_dir)

if __name__ == '__main__':
    main()
