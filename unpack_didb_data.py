import os
import argparse
import zipfile
import io
import struct
import zlib
import blowfish

# Files ending with these strings will not go through decryption or decompression.
PASS_THROUGH_PATTERNS = [
    'index.xml',
    '.MF',
]

# Files ending with these strings will go through decryption.
# The boolean value indicates if they are also compressed.
EXTENSION_CONFIG = {
    '.class': True,      
    '.xml': True,      
    '.properties': True,      
    '.sk2': True,      
    '.sk3': True,      
    '.png': False,
    '.jpg': False,
}

# The key for the Blowfish algorithm is stored as bytes of base64 in some plugin, here it's already decoded as hex.
cipher = blowfish.Cipher(bytearray.fromhex('92 EA 3B F7 9B 5B 59 C4 AA 23 1F C7 5B C6 88 89 6C AB 26 2E 77 B5 6B 0A 0F 88 43 D8 8D EF 8C 40 77 ED E3 2B 9C F1 5D 0D 04 DD 25 F1 F9 82 7A A0 EE C2 8F 5C 43 AC B6 38'))


# Get file configuration based on filename/extension
def is_pass_through(filename):
    for pattern in PASS_THROUGH_PATTERNS:
        if filename.endswith(pattern):
            return True
    return False
def get_processing_rule(filename):
    for pattern, is_compressed in EXTENSION_CONFIG.items():
        if filename.lower().endswith(pattern.lower()):
            return True, is_compressed
    return False, False

# Blowfish ECB decryption
def decrypt_bytes(data):
    if len(data) % 8 != 0:
        data += bytes(8 - (len(data) % 8))
    return b''.join(cipher.decrypt_ecb(data))

# Change the type of "extra" fields in archives to something else.
# These fields were used originally as some signatures for integrity checking, but they make the zipfile module complain.
def patch_headers(data):
    data = bytearray(data)
    
    offset = 0
    while True:
        offset = data.find(b'\x50\x4B\x03\x04', offset)
        if offset == -1: break
        try:
            fname_len = struct.unpack('<H', data[offset+26:offset+28])[0]
            extra_len = struct.unpack('<H', data[offset+28:offset+30])[0]
            if extra_len >= 4:
                extra_start = offset + 30 + fname_len
                data[extra_start:extra_start+2] = bytearray.fromhex('BEEF')
                data[extra_start+2:extra_start+4] = struct.pack('<H', extra_len - 4)
        except: pass
        offset += 4

    # Patch "central directory headers".
    offset = 0
    while True:
        offset = data.find(b'\x50\x4B\x01\x02', offset)
        if offset == -1: break
        try:
            fname_len = struct.unpack('<H', data[offset+28:offset+30])[0]
            extra_len = struct.unpack('<H', data[offset+30:offset+32])[0]
            if extra_len >= 4:
                extra_start = offset + 46 + fname_len
                data[extra_start:extra_start+2] = b'\xFE\xCA'
                data[extra_start+2:extra_start+4] = struct.pack('<H', extra_len - 4)
        except: pass
        offset += 4
        
    return bytes(data)

# Seems like they rolled their own strange multi-class file format.
# Instead of having the regular 0xCAFEBABE header, they have 0xCAFE0D15 (I assume 0D15 means ODIS, funny).
def unpack_special_container(data, parent_filename):
    if not data.startswith(b'\xCA\xFE\x0D\x15'):
        return None

    results = []
    offset = 4
    
    # All numbers are stored big-endian.
    try:
        # Number of classes (unsigned short)
        count = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        
        # The sub-classes must start with the name of the parent-class.
        base_parent_name = os.path.splitext(parent_filename)[0]

        for _ in range(count):
            # Filename length (unsigned short)
            fname_len = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2
            
            # Filename (of the current sub-class)
            fname = data[offset:offset+fname_len].decode('utf-8')
            offset += fname_len
            
            if not fname.startswith(base_parent_name):
                print(f'    [!] Warning: Inner file "{fname}" does not start with container name "{base_parent_name}"')

            # The filenames also don't contain the extension, so add it here.
            fname += '.class'

            # Data length (int)
            data_len = struct.unpack('>I', data[offset:offset+4])[0]
            offset += 4
            
            # Data
            class_bytes = data[offset:offset+data_len]
            offset += data_len
            
            if not class_bytes.startswith(b'\xCA\xFE\xBA\xBE'):
                 print(f'    [!] Warning: Inner file "{fname}" does not have CAFEBABE header.')

            results.append((fname, class_bytes))
            
    except Exception as e:
        print(f'    [!] Error unpacking container {parent_filename}: {e}')
        return None

    return results

# Unpack every file in the archive
def process_archive(archive_path, output_dir):
    try:
        with open(archive_path, 'rb') as f:
            raw_data = f.read()

        safe_data = patch_headers(raw_data)

        with zipfile.ZipFile(io.BytesIO(safe_data), 'r') as zf:
            print(f'[+] Unpacking: {archive_path}')
            
            for file_info in zf.infolist():
                # Skip directories.
                if file_info.filename.endswith('/'):
                    continue
                
                # Prepare output paths.
                target_path_base = os.path.join(output_dir, file_info.filename)
                target_dir = os.path.dirname(target_path_base)
                os.makedirs(target_dir, exist_ok=True)

                try:
                    # Skip the file if it doesn't need to be unpacked.
                    if is_pass_through(file_info.filename):
                        content = zf.read(file_info)
                        with open(target_path_base, 'wb') as f_out:
                            f_out.write(content)
                        continue 
                    
                    # Check whether the file also needs to be decompressed after decryption.
                    should_process, needs_decompression = get_processing_rule(file_info.filename)
                    
                    # If the file type is not found in the list, stop the script.
                    if not should_process:
                        raise ValueError(f'Unknown file extension found: "{file_info.filename}"')

                    # Read the file's bytes from the archive and decrypt them.
                    encrypted_bytes = zf.read(file_info)
                    content = decrypt_bytes(encrypted_bytes)
                    
                    # If necessary, decompress the bytes (GZIP, but use ZLIB to ignore garbage bytes at the end of the file).
                    if needs_decompression:
                        try:
                            content = zlib.decompress(content, wbits=31)
                        except Exception as gz_err:
                            print(f'    [!] Decompress failed for {file_info.filename} (saving raw decrypted): {gz_err}')
                            with open(target_path_base + '.decomp_failed', 'wb') as f_out:
                                f_out.write(content)
                            continue

                    # If the .class file is their special multi-class file type, unpack each sub-class as its own file.
                    parent_fname = os.path.basename(file_info.filename)
                    inner_files = unpack_special_container(content, parent_fname)
                    if inner_files is not None:
                        for inner_name, inner_data in inner_files:
                            out_path = os.path.join(target_dir, os.path.basename(inner_name))
                            with open(out_path, 'wb') as f_out:
                                f_out.write(inner_data)
                    
                    # Otherwise, write the decypted (+ decompressed) bytes to the output file.
                    else:
                        with open(target_path_base, 'wb') as f_out:
                            f_out.write(content)
                        
                except Exception as e:
                    print(f'    [-] Error {file_info.filename}: {e}')

    except Exception as e:
        if 'Unknown file extension' in str(e):
            raise e
        print(f'[!] Failed archive {archive_path}: {e}')

def main(input_root, output_root):
    input_root = os.path.abspath(input_root)
    output_root = os.path.abspath(output_root)

    print(f'Scanning: {input_root}')
    for root, dirs, files in os.walk(input_root):
        for file in files:
            # We only care about archives.
            if file.lower().endswith(('.jar', '.zip')):
                full_path = os.path.join(root, file)
                relative_path = os.path.relpath(root, input_root)
                
                archive_dump_folder = os.path.join(output_root, relative_path, f'{file}_extracted')

                # Check if the archive has already been unpacked.
                if os.path.exists(archive_dump_folder):
                    print(f'[.] Skipping {file} (already unpacked)')
                    continue

                os.makedirs(archive_dump_folder, exist_ok=True)
                
                process_archive(full_path, archive_dump_folder)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('input_folder')
    parser.add_argument('output_folder')
    args = parser.parse_args()
    
    if os.path.exists(args.input_folder):
        main(args.input_folder, args.output_folder)
    else:
        print('Error: Input folder not found.')
