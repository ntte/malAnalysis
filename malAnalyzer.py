import hashlib
import magic
import pefile
import os

def getFileHashes(filepath):
    hashes = {'md5': hashlib.md5(), 'sha256': hashlib.sha256()}
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            for algo in hashes.values():
                algo.update(chunk)
    return {name: h.hexdigest() for name, h in hashes.items()}

def detectFileType(filepath):
    return magic.from_file(filepath)

def analyzePeHeaders(filepath):
    try:
        pe = pefile.PE(filepath)
        return {
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "compile_time": pe.FILE_HEADER.TimeDateStamp,
            "sections": [(s.Name.decode().strip(), hex(s.VirtualAddress)) for s in pe.sections]
        }
    except Exception as e:
        return {"error": str(e)}
    
if __name__ == '__main__':
    path = input("Enter path to suspicious file: ").strip()
    if not os.path.isfile(path):
        print("Invalid file path.")
        exit(1)

    print("\n File Hashes:")
    print(getFileHashes(path))

    print("\n File Type:")
    print(detectFileType(path))

    print("\n PE Header Info:")
    print(analyzePeHeaders(path))
