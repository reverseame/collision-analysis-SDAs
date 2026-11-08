# Description: Script to show graphs with the distribution of the bytes of two
#              pages that have collided.
# Phase: Analysis
# Author: Luis Palazón Simón

import argparse
import subprocess
import matplotlib.pyplot as plt
import os

PAGE_SIZE = 4096
DIR_GRAPHS = '../auto/'

# Set Matplotlib to use LaTeX
plt.rcParams.update({
    "text.usetex": True,
    "font.family": "serif",
    "font.serif": ["Times"],
    "font.sans-serif": ["Computer Modern Sans serif"],
    "font.monospace": ["Computer Modern Typewriter"],
    "axes.labelsize": 28,
    "font.size": 28,
    "legend.fontsize": 24,
    "xtick.labelsize": 20,
    "ytick.labelsize": 20,
    "figure.figsize": (24, 12)
})

def showBytesFrequency(content1, content2, numPage1, numPage2):
    # Calculate the distribution of bytes
    dist1 = {}
    dist2 = {}
    for i in range(PAGE_SIZE):
        if content1[i] in dist1:
            dist1[content1[i]] += 1
        else:
            dist1[content1[i]] = 1
        if content2[i] in dist2:
            dist2[content2[i]] += 1
        else:
            dist2[content2[i]] = 1

    fig, (ax1, ax2) = plt.subplots(2, 1)

    # Subplot 1
    ax1.bar(dist1.keys(), dist1.values(), color='b')
    ax1.set_xlabel('Byte')
    ax1.set_ylabel('Frecuencia')
    ax1.set_title('Frecuencia de bytes de la página {}'.format(numPage1))

    # Subplot 2
    ax2.bar(dist2.keys(), dist2.values(), color='r')
    ax2.set_xlabel('Byte')
    ax2.set_ylabel('Frecuencia')
    ax2.set_title('Frecuencia de bytes de la página {}'.format(numPage2))

    plt.tight_layout()
    plt.show()

    # Verify if the directory exists
    directory = DIR_GRAPHS+'/{}_{}'.format(numPage1, numPage2)
    if not os.path.exists(directory):
        os.makedirs(directory)
    plt.savefig(DIR_GRAPHS+'/{}_{}/frecuencia_bytes.png'.format(numPage1, numPage2))


def showBytesDistributions(content1, content2, numPage1, numPage2, slide1, slide2, displayLines = False):
    '''
    Show in graph:
        - X axis: byte number within the page
        - Y axis: byte value
    representing in different colors the bytes of one page and the other.
    '''
    assert slide1 == 0 or slide2 == 0, 'Error: no se puede desplazar ambos archivos'
    format = '' if displayLines else '.'
    addLabel1 = ''
    addLabel2 = ''
    graph_suffix = ''
    # Initialize lists to store the bytes
    bytes1 = []
    bytes2 = []
    # Fill the lists with the bytes of the pages
    for i in range(PAGE_SIZE):
        bytes1.append(content1[i])
        bytes2.append(content2[i])
    plt.figure()
    # Apply slide if necessary
    if slide1 > 0:
        bytes1 = [-10]*slide1 + bytes1
        bytes2 = bytes2 + [-10]*slide1
        title = 'Distribución de bytes de las páginas {} y {} (desp. {}B)'.format(numPage1, numPage2, slide1)
        addLabel1 = ' (desp. {}B)'.format(slide1)
        plt.axvline(x=slide1, color='g', linestyle='--')
        plt.axvline(x=PAGE_SIZE, color='g', linestyle='--')
        graph_suffix = '_slide1_{}'.format(slide1)
    elif slide2 > 0:
        bytes2 = [-10]*slide2 + bytes2
        bytes1 = bytes1 + [-10]*slide2
        title = 'Distribución de bytes de las páginas {} y {} (desp. {}B)'.format(numPage1, numPage2, slide2)
        addLabel2 = ' (desp. {}B)'.format(slide2)
        plt.axvline(x=slide2, color='g', linestyle='--')
        plt.axvline(x=PAGE_SIZE, color='g', linestyle='--')
        graph_suffix = '_slide2_{}'.format(slide2)
    else:
        title = 'Distribución de bytes de las páginas {} y {}'.format(numPage1, numPage2)
    # Show the graph
    plt.plot(range(PAGE_SIZE+max(slide1,slide2)), bytes1, 'b'+format, label='Página {}'.format(numPage1)+addLabel1)
    plt.plot(range(PAGE_SIZE+max(slide1,slide2)), bytes2, 'r'+format, label='Página {}'.format(numPage2)+addLabel2)
    first = True
    for i in range(PAGE_SIZE):
        if bytes1[i] == bytes2[i]:
            if first:
                plt.plot(i, bytes1[i], 'g'+format, label='Coincidencias')
                first = False
            else:
                plt.plot(i, bytes1[i], 'g'+format)
    plt.xlabel('Número de byte')
    plt.ylabel('Valor del byte')
    plt.title(title)
    plt.legend()
    plt.show()
    # Verify if the directory exists
    directory = DIR_GRAPHS+'/{}_{}'.format(numPage1, numPage2)
    if not os.path.exists(directory):
        os.makedirs(directory)
    plt.savefig(DIR_GRAPHS+'/{}_{}/distribucion_bytes'.format(numPage1, numPage2)+graph_suffix+'.png')




if __name__ == '__main__':
    # Parse arguments
    parser = argparse.ArgumentParser(description='Busca el desplazamiento de un contenido en otro a nivel de bytes')
    parser.add_argument('numPage1', type=int, help='Número de página del primer archivo')
    parser.add_argument('numPage2', type=int, help='Número de página del segundo archivo')
    parser.add_argument('--slide1', type=int, default=0, help='Desplazamiento del primer archivo')
    parser.add_argument('--slide2', type=int, default=0, help='Desplazamiento del segundo archivo')
    args = parser.parse_args()
    # Obtener los nombres de los archivos (buscar en el directorio actual el fichero que comienza por numPage1_ y numPage2_ mediante el comando find)
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
    print('Ficheros a analizar:')
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
    if args.slide1 == 0 and args.slide2 == 0:
        showBytesFrequency(content1, content2, args.numPage1, args.numPage2)
    showBytesDistributions(content1, content2, args.numPage1, args.numPage2, args.slide1, args.slide2)