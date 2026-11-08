# Description: This script is used to test the hashes.py script with a dataset of files.
# Phase: Análisis
# Author: Luis Palazón Simón

import os
import sys
import subprocess
import argparse
import tqdm
import pandas as pd

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test hashes.py')
    parser.add_argument('x', type=int, help='Number of test to do')
    parser.add_argument('dataset', type=str, help='Dataset .xlsx to test', nargs='?')
    parser.add_argument('-read', '--readOnly', action='store_true', help='Read only mode', default=False)
    parser.add_argument('-fin', '--fin', type=int, help='Final test', default=None)
    parser.add_argument('-crop', '--crop', type=int, help='Crop bytes', default=None)
    args = parser.parse_args()

    crop = ''
    if args.crop:
        crop = ' -crop ' + str(args.crop)

    # Obtain the .dmp files from the current directory
    if not args.dataset:
        files = [f for f in os.listdir('.') if f.endswith('.dmp')]
        total = len(files)
    else:
        # args.dataset is a .xlsx file that contains a pandas dataframe
        df = pd.read_excel(args.dataset)
        files = []
        # we want to read the 'page1' column
        pages = df['page1'].tolist()
        for p in pages:
            p1 = int(p)
            res = subprocess.run(['find', '.', '-maxdepth', '1', '-type', 'f', '-name', '{}_*'.format(p1)], stdout=subprocess.PIPE)
            if res.returncode != 0:
                print('No se ha encontrado el fichero del primer número de página')
                exit(1)
            file1 = res.stdout.decode().split('\n')[0]
            files.append(file1)
        # we want to read the 'page2' column
        pages = df['page2'].tolist()
        for p in pages:
            p2 = int(p)
            res = subprocess.run(['find', '.', '-maxdepth', '1', '-type', 'f', '-name', '{}_*'.format(p2)], stdout=subprocess.PIPE)
            if res.returncode != 0:
                print('No se ha encontrado el fichero del segundo número de página')
                exit(1)
            file2 = res.stdout.decode().split('\n')[0]
            files.append(file2) 
        total = len(files)   
    if not args.fin:
        if not args.readOnly:
            # Execute the hashes.py script with each of the files
            # and the -test x argument
            os.remove('test_hashes.txt')
            for f in tqdm.tqdm(files, desc='Processing files', unit='file'):
                os.system('python2 hashes.py ' + f + ' -test ' + str(args.x) + crop + ' >> test_hashes.txt')

        # Count how many hashes of each algorithm are equal
        with open('test_hashes.txt') as f:
            countSDHASH = sum(1 for line in f if 'Hashes for algorithm SDHash are equal' in line)
        f.close()
        with open('test_hashes.txt') as f:
            countTLSH = sum(1 for line in f if 'Hashes for algorithm TLSH are equal' in line)
        f.close()
        with open('test_hashes.txt') as f:
            countSSDEEP = sum(1 for line in f if 'Hashes for algorithm SSDeep are equal' in line)
        f.close()
        if args.x:
            print('Test ' + str(args.x))
        print('SDHash equal: ' + str(countSDHASH) + ' of ' + str(total))
        print('TLSH equal: ' + str(countTLSH) + ' of ' + str(total))
        print('SSDeep equal: ' + str(countSSDEEP) + ' of ' + str(total))
    else:
        xs = range(args.x, args.fin+1)
        # remove results_test_hashes.txt if it exists
        if os.path.exists('results_test_hashes.txt'):
            os.remove('results_test_hashes.txt')
        for x in xs:
            if not args.readOnly:
                # Execute the hashes.py script with each of the files
                # and the -test x argument
                os.remove('test_hashes.txt')
                for f in tqdm.tqdm(files, desc='Processing files', unit='file'):
                    os.system('python2 hashes.py ' + f + ' -test ' + str(x) + crop + ' >> test_hashes.txt')

            # Count how many hashes of each algorithm are
            with open('test_hashes.txt') as f:
                countSDHASH = sum(1 for line in f if 'Hashes for algorithm SDHash are equal' in line)
            f.close()
            with open('test_hashes.txt') as f:
                countTLSH = sum(1 for line in f if 'Hashes for algorithm TLSH are equal' in line)
            f.close()
            with open('test_hashes.txt') as f:
                countSSDEEP = sum(1 for line in f if 'Hashes for algorithm SSDeep are equal' in line)
            f.close()
            
            # open file in append mode
            with open('results_test_hashes.txt', 'a') as f:
                f.write('Test ' + str(x) + '\n')
                f.write('SDHash equal: ' + str(countSDHASH) + ' of ' + str(total) + '\n')
                f.write('TLSH equal: ' + str(countTLSH) + ' of ' + str(total) + '\n')
                f.write('SSDeep equal: ' + str(countSSDEEP) + ' of ' + str(total) + '\n')