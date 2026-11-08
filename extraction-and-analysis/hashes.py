# Description: This script calculates hashes of a file allowing to compare them 
#              with another file or with itself with the first bytes changed.
# Phase: Analysis
# Author: Luis Palazón Simón

import argparse
import os
import sys
import subprocess
import pydeep       # ssdeep
import fuzzyhashlib # TLSH y sdhash

PREFIX = b'\x00'

def calculate_hashes(content,der):
    """

    """
    results = {}
    sumF = sum.SUM(content,options=None,algorithms=['xxx','ssdeep','tlsh','sdhash'],json=True, virtual_layout=True,derelocation=der)
    out = sumF.calculate()

    # d format: {'valid_pages': [True], 'num_valid_pages': 1, 'base_address': None, 'size': 4096, 'derelocation_time': None, 'num_pages': 1, 'algorithm': 'SSDeep', 'section': 'dump', 'virtual_address': 0, 'pe_time': '0.00065398216247558594', 'digest': [u'24:pW9VP6Xa4Xaijp8QDBgNPnuxC9KxMx6yxkxG53Yz3x5AOA/5eWTeWaThghRTIpO:M9wa2ai98QStn2GK2cAJMxwcdbYIO'], 'mod_name': None, 'preprocess': 'Raw', 'digesting_time': ['0.00162696838378906250']}
    # print("{}".format("-------------------------------------------------------"))
    for d in out:
        # print("{}: {}".format(d['algorithm'], d['digest'][0]))
        # print("{}".format("-------------------------------------------------------"))
        results[d['algorithm']] = d['digest'][0]
    return results



if __name__ == "__main__":
    #Check argparse description
    parser = argparse.ArgumentParser(description="A Python script to calculate hashes of a file")
    parser.add_argument('page1', help='Número de página del primer archivo')
    parser.add_argument('-page2', help='Número de página del segundo archivo (optional)')
    parser.add_argument("-sumdir", "--sumdir", help="Folder where sum.py script is located", metavar="sumdir", default="../similarity-unrelocated-module")
    parser.add_argument("-der","--derelocation", help="Derelocation value for the SUM tool. Default value is raw", default="raw", choices= ["raw", "best"])
    parser.add_argument("-slide1", "--slide1", help="Slide value for the first file", default=0, type=int)
    parser.add_argument("-slide2", "--slide2", help="Slide value for the second file", default=0, type=int)
    parser.add_argument("-prefix", "--prefixFile", help="PREFIX file to add to the content", default=None)
    parser.add_argument("-prefixFF", "--prefixFF", help="PREFIX default to FF", action="store_true")
    parser.add_argument("-prefixAA", "--prefixAA", help="PREFIX default to AA", action="store_true")
    parser.add_argument("-test", "--test", type=int, help="Compare hashes of a page with itself with first bytes changed", default=None)
    parser.add_argument("-crop", "--crop", type=int, help="Crop the last bytes of the file/s", default=None)
    args = parser.parse_args()

    slide1 = args.slide1
    slide2 = args.slide2
    
    if args.prefixFile:
        if args.prefixFile == "8B":
            maliciousContent = b'\xD7\xCB\x81\x7C\x90\x90\x90\x90'
        elif args.prefixFile == "16B":
            maliciousContent = b'\xB8\xD7\xCB\x81\x7C\xFF\xD0\x90\x90\x90\x90\x90\x90\x90\x90\x90'
        elif args.prefixFile == "32B":
            maliciousContent = (
                b'\x31\xc0\x50\x68\x2e\x65\x78\x65\x68\x2e\x63\x6d\x64'
                b'\x89\xe3\xb8\xc0\x1e\x86\x7c\xff\xd0\x31\xc0\xb8\xd7'
                b'\xcb\x81\x7c\xff\xd0'
            )
        else:
            try:
                with open(args.prefixFile, "rb") as f:
                    maliciousContent = f.read()
                f.close()
            except Exception as e:
                print("Error while reading the prefix file: {}".format(e))
                exit(-1)
        assert len(maliciousContent) <= max(slide1,slide2), "The prefix file is larger than the slide value"

    assert slide1 == 0 or slide2 == 0, "Only one slide value can be different from 0"
    assert not (args.test and args.page2), "Test mode is only available for one page"

    try:
        sys.path.append(os.path.abspath(args.sumdir))
        aux = args.sumdir
        import sum
    except Exception as e:
        print(e)
        import traceback
        traceback.print_exc()
        exit(-1)

    # If numPage1 contains a dot, it is assumed to be a file and not a page number    
    if str(args.page1).find('.') != -1:
        file1 = args.page1
        print('Fichero a analizar: {}'.format(file1))
    else:
        # Obtain the names of the files (search in the current directory the file that starts with numPage1_ using the find command)
        page1 = int(args.page1)
        res = subprocess.Popen(['find', '.', '-maxdepth', '1', '-type', 'f', '-name', '{}_*'.format(page1)], stdout=subprocess.PIPE)
        output, _ = res.communicate()
        if res.returncode != 0:
            print('No se ha encontrado el fichero del segundo número de página')
            exit(1)
        file1 = output.decode().split('\n')[0]
    if args.page2:
        # If numPage2 contains a dot, it is assumed to be a file and not a page number
        if str(args.page2).find('.') != -1:
            file2 = args.page2
            print('Fichero a analizar: {}'.format(file2))
        else:
            # Obtain the names of the files (search in the current directory the file that starts with numPage2_ using the find command)
            page2 = int(args.page2)
            res = subprocess.Popen(['find', '.', '-maxdepth', '1', '-type', 'f', '-name', '{}_*'.format(page2)], stdout=subprocess.PIPE)
            output, _ = res.communicate()
            if res.returncode != 0:
                print('No se ha encontrado el fichero del segundo número de página')
                exit(1)
            file2 = output.decode().split('\n')[0]
            print('Ficheros a analizar:')
            print(' - {}'.format(file1))
            print(' - {}'.format(file2))


    # Try to read binary the requested file
    try:
        with open(file1, "rb") as f:
            content = f.read()
    except Exception as e:
        print("Error while reading the file: {}".format(e))
        exit(-1)

    print("Calculating hashes for file: {}".format(file1))

    if slide1 != 0:
        print("Sliding content1 {} bytes".format(slide1))
        # show the prefix used
        prefix_string = "00"
        if args.prefixFF:
            PREFIX = b'FF'
            prefix_string = "FF"
        elif args.prefixAA:
            PREFIX = b'\xAA'
            prefix_string = "AA"
        if slide1 != 0 or slide2 != 0:
            print("Prefix used by default: {}".format(prefix_string))
        if args.prefixFile:
            print("Payload file used: {}".format(args.prefixFile))
        # introduce the prefix
        if args.prefixFile:
            content = maliciousContent + content
            for _ in range(slide1-len(maliciousContent)):
                content = PREFIX + content
        else:
            for _ in range(slide1):
                content = PREFIX + content
        content = content[:-slide1]
        # write content in a file
        with open("a.dmp", "wb") as f:
            f.write(content)
        f.close()
    if args.crop:
        print("Cropping content {} bytes".format(args.crop))
        content = content[:-args.crop]
        # return to bytes

    res = calculate_hashes(content, args.derelocation)

    # If a second file is provided, calculate hashes for it
    if args.page2 or args.test:
        # Update the prefix used if it is necessary
        prefix_string = "00"
        if args.prefixFF:
            PREFIX = b'FF'
            prefix_string = "FF"
        elif args.prefixAA:
            PREFIX = b'\xAA'
            prefix_string = "AA"
        # If a second file is provided, read it
        if args.page2:
            try:
                with open(file2, "rb") as f:
                    content2 = f.read()
            except Exception as e:
                print("Error while reading the file: {}".format(e))
                exit(-1)
        else: # If not, compare the first file with itself with the first bytes changed
            content2 = content
            file2 = file1 + " (-test {}, prefix {})".format(args.test, prefix_string)
            for i in range(0, args.test):
                content2 = content2[:i] + PREFIX + content2[i+1:]
        if slide2 != 0:
            print("Sliding content2 {} bytes".format(slide2))
            # show the prefix used
            if slide1 != 0 or slide2 != 0:
                # mostrar prefix de forma visible
                print("Prefix used by default: {}".format(prefix_string))
            if args.prefixFile:
                print("Payload file used: {}".format(args.prefixFile))
            # introduce the prefix
            if args.prefixFile:
                content2 = maliciousContent + content2
                for _ in range(slide2-len(maliciousContent)):
                    content2 = PREFIX + content2
            else:
                for _ in range(slide2):
                    content2 = PREFIX + content2
            content2 = content2[:-slide2]
            # write content in a file
            with open("b.dmp", "wb") as f:
                f.write(content2)
            f.close()
        if args.crop:
            print("Cropping content2 {} bytes".format(args.crop))
            content2 = content2[:-args.crop]
        print("Calculating hashes for file: {}".format(file2))
        res2 = calculate_hashes(content2, args.derelocation)

        # Compare hashes
        print("{}".format("-------------------------------------------------------"))
        for k in res.keys():
            if res[k] == res2[k]:
                print("Hashes for algorithm {} are equal".format(k))
            else:
                print("Hashes for algorithm {} are different".format(k))
                print("Hash1: {}".format(res[k]))
                print("Hash2: {}".format(res2[k]))
            if k == "SSDeep":
                score = pydeep.compare(res[k], res2[k])
                print("Similarity score for SSDeep: {}".format(score))
            elif k == "TLSH":
                score = fuzzyhashlib.tlsh(content).compare(fuzzyhashlib.tlsh(content2))
                print("Similarity score for TLSH: {}".format(score))
            # elif k == "SDHash":
            #     print("Hash SDHash 1: {}".format(fuzzyhashlib.sdhash(content).hexdigest()))
            #     print("Hash SDHash 2: {}".format(fuzzyhashlib.sdhash(content2).hexdigest()))
            #     score = fuzzyhashlib.sdhash(content).compare(fuzzyhashlib.sdhash(content2))
            #     print("Similarity score for SDHash: {}".format(score))
            print("{}".format("-------------------------------------------------------"))
    else:
        print("{}".format("-------------------------------------------------------"))
        for k in res.keys():
            print("{} hash: {}".format(k, res[k]))
            print("{}".format("-------------------------------------------------------"))

    