import sys

LIMIT = 10
BYTES_PER_INST = 5

def mostrar_hex(path):
    with open(path, "rb") as f:
        data = f.read()
        l = LIMIT*BYTES_PER_INST if LIMIT else len(data)
        for i in range(0, l, BYTES_PER_INST):
            chunk = data[i:i+BYTES_PER_INST]
            print(chunk.hex(), end='\n')

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python mostrar_hex.py archivo.dmp")
        sys.exit(1)
    mostrar_hex(sys.argv[1])