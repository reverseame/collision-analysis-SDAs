from unicorn import *
from unicorn.x86_const import *
import logging
import os

PAGE_SIZE = 0x1000
BASE_ADDR = 0x100000
NUM_PAGES = 3
BYTES_PER_BLOCK = 10
BYTES_PER_INST = 5
SUFFIX = "_post_injection"

# Configuración básica: nivel mínimo de log y formato
logging.basicConfig(
    # Nivel mínimo que se mostrará (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    level=logging.INFO,
    # Formato de los mensajes de log
    # format='%(asctime)s - %(levelname)s - %(message)s'
    format='%(levelname)s - %(message)s'
)

def print_exploit_segments(exploit_segments):
    '''Imprimir los segmentos del exploit en formato hexadecimal.'''
    logging.info("Segmentos del exploit:")
    for i, segment in enumerate(exploit_segments):
        hex_segment = ' '.join(f"{byte:02x}" for byte in segment)
        logging.info(f"Segmento {i + 1}: {hex_segment} (tamaño: {len(segment)} bytes)")

def validate_segments(exploit_segments):
    '''Validar que los segmentos del exploit no excedan el tamaño de bloque permitido.'''
    for i, segment in enumerate(exploit_segments):
        if len(segment) > BYTES_PER_BLOCK:
            raise ValueError(f"El segmento {i} del exploit es demasiado grande para una página.")

def obtain_exploit_segments():
    '''Obtener los segmentos del exploit desde un archivo o definirlos directamente.'''
    # leer de un archivo
    with open('exploit.asm', 'rb') as f:
        exploit_data = f.read()
    # Dividir el exploit en segmentos de tamaño BYTES_PER_BLOCK-BYTES_PER_INST, 
    # excepto el útlimo segmento que puede ser hasta de BYTES_PER_BLOCK
    exploit_segments = []
    for i in range(0, len(exploit_data), BYTES_PER_BLOCK - BYTES_PER_INST):
        segment = exploit_data[i:i + BYTES_PER_BLOCK - BYTES_PER_INST]
        if segment:
            exploit_segments.append(segment)
    # Hacer que el último segmento sea de BYTES_PER_BLOCK si es necesario
    if len(exploit_segments) > 1 and len(exploit_segments[-2])+len(exploit_segments[-1]) <= BYTES_PER_BLOCK:
        exploit_segments[-2] = exploit_segments[-2] + exploit_segments[-1]
        exploit_segments.pop()

    print_exploit_segments(exploit_segments)
    validate_segments(exploit_segments)

    return exploit_segments


def build_jmp(from_addr, to_addr):
    '''Construir una instrucción jmp relativa de BYTES_PER_INST bytes.'''
    offset = to_addr - (from_addr + BYTES_PER_INST)  # jmp es relativa al final de la instrucción
    return b"\xE9" + offset.to_bytes(BYTES_PER_INST-1, byteorder='little', signed=True)


def mem_map(mu, exploit_segments):
    '''Asignar memoria y escribir código en las páginas desde archivos .dmp, luego inyectar el exploit.'''
    for i in range(NUM_PAGES):
        addr = BASE_ADDR + i * PAGE_SIZE  # Dirección base de la página
        dmp_file = f"dmps/page_{i+1}.dmp"

        # Cargar el contenido del .dmp
        if not os.path.exists(dmp_file):
            logging.critical(f"No se encontró el archivo {dmp_file}")
            raise FileNotFoundError(f"Archivo no encontrado: {dmp_file}")

        with open(dmp_file, "rb") as f:
            page = bytearray(f.read())

        if len(page) != PAGE_SIZE:
            logging.error(f"{dmp_file} no tiene el tamaño esperado de {PAGE_SIZE} bytes")
            raise ValueError(f"Tamaño incorrecto en {dmp_file}")

        logging.debug(f"Mapeando página {i+1} en {hex(addr)} hasta {hex(addr + PAGE_SIZE)}")
        mu.mem_map(addr, PAGE_SIZE)

        # Dirección del salto (si no es la última)
        if i < NUM_PAGES - 1:
            next_page_addr = BASE_ADDR + (i + 1) * PAGE_SIZE
            jmp_instr = build_jmp(addr + BYTES_PER_BLOCK - BYTES_PER_INST, next_page_addr)
            logging.debug(f"Página {i+1} salto a {hex(next_page_addr)} desde {hex(addr)}")
        else:
            jmp_instr = b""

        # Insertar exploit + jmp sobrescribiendo los primeros bytes del .dmp cargado
        if len(exploit_segments[i]) <= BYTES_PER_BLOCK - BYTES_PER_INST:
            page[0:BYTES_PER_BLOCK - BYTES_PER_INST] = exploit_segments[i][:BYTES_PER_BLOCK - BYTES_PER_INST]
            page[BYTES_PER_BLOCK - BYTES_PER_INST:BYTES_PER_BLOCK] = jmp_instr
        else:
            if i < NUM_PAGES - 1:
                logging.error(f"El segmento de exploit debe ser de {BYTES_PER_BLOCK - BYTES_PER_INST}B o menos para páginas intermedias.")
                raise ValueError("Exploit demasiado grande para página intermedia.")
            page[0:len(exploit_segments[i])] = exploit_segments[i]

        # Escribir en memoria el contenido de la página modificada
        mu.mem_write(addr, bytes(page))


def hook_intr(uc, intno, _):
    """Hook para manejar interrupciones, en este caso INT 3."""
    if intno == 3:
        eax = uc.reg_read(UC_X86_REG_EAX)
        ebx = uc.reg_read(UC_X86_REG_EBX)
        ecx = uc.reg_read(UC_X86_REG_ECX)
        logging.info(f"INT 3 alcanzado. EAX = {eax}, EBX = {ebx}, ECX = {ecx}")
        uc.emu_stop()

        assert eax == 1, "EAX debe ser 1 en la página 1"
        assert ebx == 2, "EBX debe ser 2 en la página 2"
        assert ecx == 3, "ECX debe ser 3 en la página 3"
        logging.info("Validación exitosa.")


def hook_code(uc, address, size, _):
    """Hook para capturar la ejecución de código."""
    code = uc.mem_read(address, size) # Lee bytes de la instrucción
    logging.info(f"Ejecutando instrucción en 0x{address:x}, tamaño: {size} bytes, código: {code.hex()}")


def save_memory_dump():
    """Volcar la memoria de las páginas a archivos .dmp."""
    logging.info("Volcando memoria de las páginas a archivos .dmp (después de la emulación)...")
    for i in range(NUM_PAGES):
        addr = BASE_ADDR + i * PAGE_SIZE
        # Leer la memoria de la página completa
        data = mu.mem_read(addr, PAGE_SIZE)
        # Guardar en archivo .dmp
        file = f"dmps/page_{i+1}{SUFFIX}.dmp"
        with open(file, "wb") as f:
            f.write(data)
        logging.debug(f"Página {i+1} volcadas en {file}")



if __name__ == "__main__":
    exploit_segments = obtain_exploit_segments()

    # Creamos emulador
    mu = Uc(UC_ARCH_X86, UC_MODE_32)

    # Asignamos memoria
    mem_map(mu, exploit_segments)

    # Añadimos hooks
    mu.hook_add(UC_HOOK_INTR, hook_intr)
    mu.hook_add(UC_HOOK_CODE, hook_code)

    # Emulación
    logging.info("Comenzando emulación desde página 1...")
    mu.emu_start(BASE_ADDR, 0)
    logging.info("Emulación finalizada.")

    # Volcar después de la emulación
    save_memory_dump()  

