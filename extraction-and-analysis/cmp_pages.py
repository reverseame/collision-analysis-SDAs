# Description: Searches for the displacement of the content of one page in another at 
#              the byte level or compares byte by byte if a reliable one is not found
# Phase: Analysis
# Author: Luis Palazón Simón

import argparse
import subprocess
import tempfile
import os

PAGE_SIZE = 4096
THRESHOLD = 2


def searchDisplacement(content1, content2, displacement, over1):
    '''
    parameters:
        content1: bytes
        content2: bytes
        displacement: int
        over1: bool, true if the displacement is over content1, false otherwise
    return:
        bool, true if the displacement works
    '''
    try:
        if over1:
            for i in range(PAGE_SIZE-displacement):
                if content1[i] != content2[i+displacement]:
                    return False
        else: # sobre2
            for i in range(PAGE_SIZE-displacement):
                if content1[i+displacement] != content2[i]:
                    return False
        return True
    except IndexError:
        print('Error: desplazamiento fuera de rango')
        print('valor de desplazamiento: {}'.format(displacement))
        print('longitud de content1: {}'.format(len(content1)))
        print('longitud de content2: {}'.format(len(content2)))
        exit(1)

def searchDisplacementThreshold(content1, content2, displacement, over1, threshold=2):
    '''
    parameters:
        content1: bytes
        content2: bytes
        displacement: int
        over1: bool, true if the displacement is over content1, false otherwise
    return:
        bool, true if the displacement works with a threshold of threshold bytes
    '''
    diffbytes = 0
    try:
        if over1:
            for i in range(PAGE_SIZE-displacement):
                if content1[i] != content2[i+displacement]:
                    diffbytes += 1
                    if diffbytes > threshold:
                        return False, diffbytes
        else: # sobre2
            for i in range(PAGE_SIZE-displacement):
                if content1[i+displacement] != content2[i]:
                    diffbytes += 1
                    if diffbytes > threshold:
                        return False, diffbytes
        return True, diffbytes
    except IndexError:
        print('Error: desplazamiento fuera de rango')
        print('valor de desplazamiento: {}'.format(displacement))
        print('longitud de content1: {}'.format(len(content1)))
        print('longitud de content2: {}'.format(len(content2)))
        exit(1)

def cmpBytes(content1, content2):
    '''
    parameters:
        content1: bytes
        content2: bytes
    return:
        bool, true if the contents are equal byte by byte in more than 90%
    '''
    eq = 0
    for i in range(PAGE_SIZE):
        if content1[i] == content2[i]:
            eq += 1
    return eq > PAGE_SIZE*0.9

def obtainDifferentBytes(content1, content2):
    '''
    parameters:
        content1: bytes
        content2: bytes
    return:
        list of tuples, [(pos, byte1, byte2), ...]
    '''
    diff = []
    for i in range(PAGE_SIZE):
        if content1[i] != content2[i]:
            diff.append((i, content1[i], content2[i]))
    return diff


def colordiff_files(file1, file2):
    try:
        # Generate hex dump of the two files using xxd
        hex_dump1 = subprocess.run(['xxd', file1], capture_output=True, check=True).stdout
        hex_dump2 = subprocess.run(['xxd', file2], capture_output=True, check=True).stdout
        
        # Create temporary files to store the hex dumps
        with tempfile.NamedTemporaryFile(delete=False) as temp1, tempfile.NamedTemporaryFile(delete=False) as temp2:
            temp1.write(hex_dump1)
            temp2.write(hex_dump2)
            temp1_path = temp1.name
            temp2_path = temp2.name
        
        # Use colordiff to colorize the diff output of the two hex dump files
        colordiff_output = subprocess.run(['colordiff', '-y', temp1_path, temp2_path], capture_output=True, text=True, check=True).stdout
        
        # Print the final colorized diff output
        print(colordiff_output)
    
    except subprocess.CalledProcessError as e:
        # print(f"An error occurred: {e}")
        # print("Output:")
        print(e.output)

    finally:
        # Cleanup temporary files
        try:
            os.remove(temp1_path)
            os.remove(temp2_path)
        except NameError:
            pass

def mainRetDesc(numPage1, numPage2):
    found = False
    warning = False
    desc = "undefined"
    # Obtain the names of the files (search in the current directory the file that starts with numPage1_ and numPage2_ using the find command)
    res = subprocess.run(['find', '.', '-maxdepth', '1', '-type', 'f', '-name', '{}_*'.format(numPage1)], stdout=subprocess.PIPE)
    if res.returncode != 0:
        print('No se ha encontrado el fichero del primer número de página')
        exit(1)
    file1 = res.stdout.decode().split('\n')[0]
    res = subprocess.run(['find', '.', '-maxdepth', '1', '-type', 'f', '-name', '{}_*'.format(numPage2)], stdout=subprocess.PIPE)
    if res.returncode != 0:
        print('No se ha encontrado el fichero del segundo número de página')
        exit(1)
    file2 = res.stdout.decode().split('\n')[0]
    print('Ficheros a comparar:')
    print(' - {}'.format(file1))
    print(' - {}'.format(file2))
    # Read files
    with open(file1, 'rb') as f:
        content1 = f.read()
    f.close()
    with open(file2, 'rb') as f:
        content2 = f.read()
    f.close()
    if not ( len(content1) == PAGE_SIZE and len(content2) == PAGE_SIZE ):
        print('Error: los ficheros no tienen el tamaño de página esperado')
        print('longitud de content1: {}'.format(len(content1)))
        print('longitud de content2: {}'.format(len(content2)))
        return 'Error: los ficheros no tienen el tamaño de página esperado'
    # Search for displacement or make the byte to byte comparison:
    # - Search for displacement
    for i in range(PAGE_SIZE):
        if searchDisplacement(content1, content2, i, True):
            print('Necesario desplazamiento de {}B sobre el primer archivo'.format(i))
            found = True
            desc = r'$\Delta = {}$ (1)'.format(i)
            if i > PAGE_SIZE*0.5:
                warning = True
                print('\033[93mWarning: el desplazamiento es muy grande (mayor al 50% del tamaño de página) por lo que puede no ser correcto.\033[0m')
            break
        elif searchDisplacement(content1, content2, i, False):
            print('Necesario desplazamiento de {}B sobre el segundo archivo'.format(i))
            found = True
            desc = r'$\Delta = {}$ (2)'.format(i)
            if i > PAGE_SIZE*0.5:
                warning = True
                print('\033[93mWarning: el desplazamiento es muy grande (mayor al 50% del tamaño de página) por lo que puede no ser correcto.\033[0m')
            break
    # - Byte to byte comparison
    if not found or warning:
        if not found:
            print('No se ha encontrado desplazamiento, comparando byte a byte...')
        else:
            print('Se ha encontrado un desplazamiento poco fiable, se recomienda comparar byte a byte...')
        if cmpBytes(content1, content2):
            print('> Los contenidos son iguales byte a byte en más de un 90%')
            res = obtainDifferentBytes(content1, content2)
            print('> Bytes diferentes ({}):'.format(len(res)))
            for i in res:
                print('  - Posición: {}, Byte en el primer archivo: {}, Byte en el segundo archivo: {}'.format(i[0], hex(i[1]), hex(i[2])))
            if len(res) == 0:
                print('> No hay diferencias')
                print('> ¿Quiere ver la comparativa global? [y/n]')
                if input() == 'y':
                    print('> Comparando ficheros...')
                    colordiff_files(file1, file2)
            else:
                desc = '{}B diferentes'.format(len(res))
        else:
            print('> Los contenidos tampoco son iguales byte a byte en más de un 90%')
            print('> Probando el buscador de desplazamientos con un umbral de {} bytes...'.format(THRESHOLD))
            foundThreshold = False
            for i in range(PAGE_SIZE):
                res, diffbytes = searchDisplacementThreshold(content1, content2, i, True, THRESHOLD)
                if res:
                    print('   Necesario desplazamiento de {}B sobre el primer archivo ({} bytes diferentes)'.format(i, diffbytes))
                    foundThreshold = True
                    desc = r'$\Delta = {}$ (1) + {}B diferentes'.format(i, diffbytes)
                    break
                res, diffbytes = searchDisplacementThreshold(content1, content2, i, False, THRESHOLD)
                if res:
                    print('   Necesario desplazamiento de {}B sobre el segundo archivo ({} bytes diferentes)'.format(i, diffbytes))
                    desc = r'$\Delta = {}$ (2) + {}B diferentes'.format(i, diffbytes)
                    foundThreshold = True
                    break
            if not foundThreshold:
                desc = 'undefined'
                # print('> ¿Quiere ver la comparativa global? [y/n]')
                # if input() == 'y':
                #     print('> Comparando ficheros...')
                #     colordiff_files(file1, file2)
                print('> No se ha encontrado desplazamiento ni coincidencia byte a byte')
    return desc

if __name__ == '__main__':
    found = False
    warning = False
    desc = "undefined"
    # Parse arguments
    parser = argparse.ArgumentParser(description='Busca el desplazamiento de un contenido en otro a nivel de bytes')
    parser.add_argument('numPage1', type=int, help='Número de página del primer archivo')
    parser.add_argument('numPage2', type=int, help='Número de página del segundo archivo')
    args = parser.parse_args()
    # Obtain the names of the files (search in the current directory the file that starts with numPage1_ and numPage2_ using the find command)
    res = subprocess.run(['find', '.', '-maxdepth', '1', '-type', 'f', '-name', '{}_*'.format(args.numPage1)], stdout=subprocess.PIPE)
    if res.returncode != 0:
        print('No se ha encontrado el fichero del primer número de página')
        exit(1)
    file1 = res.stdout.decode().split('\n')[0]
    res = subprocess.run(['find', '.', '-maxdepth', '1', '-type', 'f', '-name', '{}_*'.format(args.numPage2)], stdout=subprocess.PIPE)
    if res.returncode != 0:
        print('No se ha encontrado el fichero del segundo número de página')
        exit(1)
    file2 = res.stdout.decode().split('\n')[0]
    print('Ficheros a comparar:')
    print(' - {}'.format(file1))
    print(' - {}'.format(file2))
    # Read files
    with open(file1, 'rb') as f:
        content1 = f.read()
    f.close()
    with open(file2, 'rb') as f:
        content2 = f.read()
    f.close()
    assert len(content1) == PAGE_SIZE and len(content2) == PAGE_SIZE, 'Error: los ficheros no tienen el tamaño de página esperado'
    # Search for displacement or make the byte to byte comparison:
    # - Search for displacement
    for i in range(PAGE_SIZE):
        if searchDisplacement(content1, content2, i, True):
            print('Necesario desplazamiento de {}B sobre el primer archivo'.format(i))
            found = True
            desc = 'desplazamiento de {}B (1)'.format(i)
            if i > PAGE_SIZE*0.5:
                warning = True
                print('\033[93mWarning: el desplazamiento es muy grande (mayor al 50% del tamaño de página) por lo que puede no ser correcto.\033[0m')
            break
        elif searchDisplacement(content1, content2, i, False):
            print('Necesario desplazamiento de {}B sobre el segundo archivo'.format(i))
            found = True
            desc = 'desplazamiento de {}B (2)'.format(i)
            if i > PAGE_SIZE*0.5:
                warning = True
                print('\033[93mWarning: el desplazamiento es muy grande (mayor al 50% del tamaño de página) por lo que puede no ser correcto.\033[0m')
            break
    # - Byte to byte comparison
    if not found or warning:
        if not found:
            print('No se ha encontrado desplazamiento, comparando byte a byte...')
        else:
            print('Se ha encontrado un desplazamiento poco fiable, se recomienda comparar byte a byte...')
        if cmpBytes(content1, content2):
            print('> Los contenidos son iguales byte a byte en más de un 90%')
            res = obtainDifferentBytes(content1, content2)
            print('> Bytes diferentes ({}):'.format(len(res)))
            for i in res:
                print('  - Posición: {}, Byte en el primer archivo: {}, Byte en el segundo archivo: {}'.format(i[0], hex(i[1]), hex(i[2])))
            if len(res) == 0:
                print('> No hay diferencias')
                print('> ¿Quiere ver la comparativa global? [y/n]')
                if input() == 'y':
                    print('> Comparando ficheros...')
                    colordiff_files(file1, file2)
            else:
                desc = '{}B diferentes'.format(len(res))
        else:
            print('> Los contenidos tampoco son iguales byte a byte en más de un 90%')
            print('> Probando el buscador de desplazamientos con un umbral de {} bytes...'.format(THRESHOLD))
            foundThreshold = False
            for i in range(PAGE_SIZE):
                res, diffbytes = searchDisplacementThreshold(content1, content2, i, True, THRESHOLD)
                if res:
                    print('   Necesario desplazamiento de {}B sobre el primer archivo ({} bytes diferentes)'.format(i, diffbytes))
                    foundThreshold = True
                    desc = 'desplazamiento de {}B (1) + {}B diferentes'.format(i, diffbytes)
                    break
                res, diffbytes = searchDisplacementThreshold(content1, content2, i, False, THRESHOLD)
                if res:
                    print('   Necesario desplazamiento de {}B sobre el segundo archivo ({} bytes diferentes)'.format(i, diffbytes))
                    desc = 'desplazamiento de {}B (2) + {}B diferentes'.format(i, diffbytes)
                    foundThreshold = True
                    break
            if not foundThreshold:
                desc = 'undefined'
                # print('> ¿Quiere ver la comparativa global? [y/n]')
                # if input() == 'y':
                #     print('> Comparando ficheros...')
                #     colordiff_files(file1, file2)
                print('> No se ha encontrado desplazamiento ni coincidencia byte a byte')
    