import tlsh
import ssdeep
import subprocess
import argparse
from emulate import SUFFIX

def hash_tlsh(path):
    with open(path, 'rb') as f:
        data = f.read()
    h = tlsh.hash(data)
    return h

def hash_ssdeep(path):
    with open(path, 'rb') as f:
        data = f.read()
    h = ssdeep.hash(data)
    return h

def hash_sdhash(path):
    result = subprocess.run(['sdhash', path], capture_output=True, text=True)
    result = result.stdout.strip()
    result = result.split(':')[-1]  # Obtener solo el hash
    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Hash files using TLSh, SSDeep, and SDHash.')
    parser.add_argument('file', type=str, help='Path to the original file to hash')
    parser.add_argument('-s', '--show_hashes', action='store_true', help='Show hashes')
    args = parser.parse_args()

    file_path_ori = args.file
    file_path_dst = file_path_ori.replace('.dmp', SUFFIX + '.dmp')

    print(f"Hashing original file: {file_path_ori}")
    print(f"Hashing destination file: {file_path_dst}")

    tlsh_hash_ori = hash_tlsh(file_path_ori)
    tlsh_hash_dst = hash_tlsh(file_path_dst)
    ssdeep_hash_ori = hash_ssdeep(file_path_ori)
    ssdeep_hash_dst = hash_ssdeep(file_path_dst)
    sdhash_ori = hash_sdhash(file_path_ori)
    sdhash_dst = hash_sdhash(file_path_dst)

    # Comparar hashes
    if args.show_hashes:
        print(f"TLSh Original: {tlsh_hash_ori}")
        print(f"TLSh Destino: {tlsh_hash_dst}")
        print(f"SSDeep Original: {ssdeep_hash_ori}")
        print(f"SSDeep Destino: {ssdeep_hash_dst}")
        print(f"SDHash Original: {sdhash_ori}")
        print(f"SDHash Destino: {sdhash_dst}")

    print("\nComparación de hashes:")
    print(f"TLSh iguales: {tlsh_hash_ori == tlsh_hash_dst}")
    print(f"SSDeep iguales: {ssdeep_hash_ori == ssdeep_hash_dst}")
    print(f"SDHash iguales: {sdhash_ori == sdhash_dst}")
    
    