import os
import shutil

N_PAGES = 3  # Número de páginas a copiar
NULL_BYTES = 10  # Número mínimo de primeros bytes nulos a buscar

SRC_DIR = 'dmps_win'  # Directorio de origen
DEST_DIR = 'dmps'  # Directorio de destino

def copiar_dmp_nulos(origen, destino, N_PAGES, NULL_BYTES):
    archivos = [f for f in os.listdir(origen) if f.endswith('.dmp')]
    copiados = 0
    for archivo in archivos:
        if copiados >= N_PAGES:
            break
        ruta = os.path.join(origen, archivo)
        with open(ruta, 'rb') as f:
            bytes_leidos = f.read(NULL_BYTES)
            if bytes_leidos == b'\x00' * NULL_BYTES:
                shutil.copy2(ruta, os.path.join(destino, "page_{}.dmp".format(copiados + 1)))
                copiados += 1

copiar_dmp_nulos(SRC_DIR, DEST_DIR, N_PAGES, NULL_BYTES)