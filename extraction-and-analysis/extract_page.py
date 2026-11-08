# Description: Script to extract a page from its module
# Phase: Extraction
# Author: Luis Palazón Simón

from zipfile import ZipFile,ZIP_DEFLATED
import argparse
import os
import logging
import sys
from tempfile import mkdtemp,gettempdir
import shutil
import stat
import re
from datetime import datetime
from mysql.connector import connect
import configparser as cg

PAGE_SIZE = 4096
wrong_zips = []


def read_config(cfg_file):
    """Reads a configuration file and it's fields

    Args:
        cfg_file (string): Path of the config file

    Returns:
        tuple: Host,username and password
    """
    config = get_config_file(cfg_file)
    dbinfo = config['DBINFO']
    # Host
    host = dbinfo['host']
    logger.debug("Host: {}".format(host))
    # User and password
    user = dbinfo['user']
    logger.debug("Username: {}".format(user))
    pwd = dbinfo['pwd']
    logger.debug("Password: {}".format(pwd))
    dbname = dbinfo['dbname']
    logger.debug("Database name: {}".format(dbname))
    return host, user, pwd, dbname


def get_config_file(path):
    """Reads a configuration file 

    Args:
        path (string): Path where the configuration file is located

    Returns:
        dict : Returns a configuration file fields
    """
    logger.debug("Reading configuration file from {}".format(path))
    if os.path.exists(path):
        print("[+] Config file found, continuing...")
        config = cg.ConfigParser()
        config.read(path)
    else:
        print("[-] Config file not found :(, exiting now...")
        sys.exit(1)
    return config


def read_bytes_from_page(file, num_page, page_size=PAGE_SIZE):
    """Reads a page from a file

    Args:
        file (string): Path of the file
        num_page (int): Number of the page
        [opt.] page_size (int): Size of the page in bytes, default is 4096

    Returns:
        bytes: Bytes of the page
    """
    page_size = page_size // 4 # 4 bytes per word
    with open(file, 'rb') as f:
        f.seek(num_page * page_size)
        return f.read(page_size)
    

def search_zip_in_folder(zip, pathzips):
    """Searches for ZIP files in a folder

    Args:
        zip (string): ZIP file to search
        pathzips (list): List of ZIP files in the folder

    Returns:
        string: ZIP file if it's found, None otherwise
    """
    for pathzip in pathzips:
        if zip in pathzip:
            return pathzip
    return None


def extract_zip(pathzips,tpfolder,dir,num_page,page_id):
    """Extracts a page from a ZIP file

    Args:
        pathzips (list): List of path of ZIP files

    Returns:
        list: Tuple containing ZIP which couldn't be processed and the error
        integer: Correct times a ZIP has been processed

    """
    err, correct, total = [], 0, len(pathzips)
    print ("[+] Searching the corresponding ZIP file...")
    zipf = search_zip_in_folder(dir, pathzips)
    if zipf is None:
        print ("[-] ZIP file not found in the folder")
        return err, correct, total
    
    #Open ZipFile
    logger.debug("Opening {}".format(os.path.basename(zipf)))
    print("Opening {}".format(os.path.basename(zipf)))
    with ZipFile(zipf,compression=ZIP_DEFLATED) as zipObj:
        logger.debug("Extracting 'joinedModuleContents' from {}...".format(os.path.basename(zipf)))
        #Check if it's and appropiate zip
        if "joinedModuleContents.dmp" in zipObj.namelist():
            zfile = zipObj.extract("joinedModuleContents.dmp",path=tpfolder)
            logger.debug("'joinedModuleContents' correctly extracted")

            with open(zfile, mode="rb") as f:
                try:
                    logger.debug("Creating SUM object")
                    sumF = sum.SUM(f.read(),options=None, algorithms=['xxx','ssdeep','tlsh','sdhash'],virtual_layout=True,derelocation="raw")
                    logger.debug("Calculating hashes for the given SUM object")
                    out = sumF.calculate()
                    
                    # Extract the page
                    print("Extracting raw page")
                    bytes = sumF.data[num_page*PAGE_SIZE:num_page*PAGE_SIZE+PAGE_SIZE]
                    
                    with open(str(page_id)+"_extracted_"+ str(num_page) + "_" + dir + ".dmp", "wb") as file:
                        file.write(bytes)
                        file.close()
                    
                    correct += 1
                    logger.debug("{} correclty processed".format(os.path.basename(zipf)))
                except Exception as e:
                    logger.exception(e)
                    err.append((os.path.basename(zipf),str(e)))
        else:
            logger.error("Can't extract 'joinedModuleContents.dmp from {}".format(os.path.basename(zipf)))
    print ("done!")
    return err, correct, total


def valid_zip(zipObj,tpfolder):
    """Checks if zip file has a correct format
    Args:
        zipObj(zipfile object): zip file with info
        tpfolder(folder): temporary folder where results are store
    Returns:
        boolean: True if it has correct format, False otherwise

    NOTE:This function is used for backward compatiblity with
        Windows Memorory extractor < 1.0.8"""
    if "results.txt" in zipObj.namelist():
        zfile = zipObj.extract("results.txt",path=tpfolder)
        logger.debug("'{}' correctly extracted".format("results.txt"))
        with open (zfile,mode="rb") as f:
            #First line and the last 6 are useless
            data = [d.strip() for d in f.readlines()[1:-6]]
            #Get first address and size
            address = int(get_hex_address(data[0]),16)
            size = int(get_hex_size(data[0]),16)
            for line in data[1:]:
                addline = int(get_hex_address(line),16)
                if addline - (address+size) != 0:
                    return False
                address = addline
                size = int(get_hex_size(line),16)
    return True


def get_hex_address(line):
	"""Returns base adress"""
	return re.split(r"_|\.",line.split()[1])[0]

def get_hex_size(line):
	"""Returns size"""
	return re.split(r"_|\.",line.split()[1])[1]


def find_fileversion(zipObj,tpfolder,zipf,nameFile="moduleFileVersionInfo.fileinfo"):
    """ Finds info file in a given zip
        
        Args:
            zipObj: ZIP file
            nameFile: name of the .fileinfo file
            tpfolder: temporary folder where info file must be extracted
        Returns:
            dict: Info inside a dictionary
    """
    if nameFile in zipObj.namelist():
        zfile = zipObj.extract(nameFile,path=tpfolder)
        logger.debug("'{}' correctly extracted".format(nameFile))
        with open(zfile,mode="rb") as f:
            data = f.readlines()
            res = []
            for line in data:
                key, value = "",""
                if "," in line:
                    key, value = line.split(",",1)
                    res.append((key,value))
                else:
                    key, value = res[-1]
                    value += line
                    res[-1] = (key,value)
            res = dict([(x[0].strip(),x[1].strip().decode('iso-8859-1').encode('utf-8')) for x in res])
    else:
        logger.error("Can't extract {} from {}".format(nameFile,os.path.basename(zipf)))
    return res


def get_all_file_paths(root,extension):
    """Finds all the files with a given extension from a given directory

    Args:
        root (string): Path where the search will start from
        extension (string): Extension of the files to be searched

    Returns:
        list: A list of string with all the paths to the searched files
    """
    paths = []
    print('[+] Searching for {} files in {} ... '.format(extension,root)),
    for root,dirs,files in os.walk(root):
        #Store the path of the DLL files in an auxiliar list
        aux = [os.path.join(root,f) for f in files if f.endswith(extension)]
        #Append the new files found
        paths.extend(aux)
    print('done!')
    return paths


def create_logger(log_level):
    """Creates a logger with a specified level

    Args:
        log_level (int): Initial level of the logger

    Returns:
        logging : Logging object 
    """
    #Log handler
    lh = logging.StreamHandler()
    #Format
    lh.setFormatter(logging.Formatter('%(levelname)s - %(name)s - %(message)s'))
    #Logger
    logger = logging.getLogger(os.path.basename(__file__))
    logger.setLevel(log_level)
    logger.addHandler(lh)
    return logger


def get_page_info(connection, page_id):
    """Obtains the module ID and page number of the page from the database

    Args:
        connection (mysql.connector.connection.MySQLConnection): Connection to the database
        page_id (int): Page ID to obtain the module ID and page number

    Returns:
        The module ID of the page and the number of the page
    """
    query = "SELECT module_id, num_page FROM pages WHERE id = {}".format(page_id)
    with connection.cursor() as cursor:
        cursor.execute(query)
        data = cursor.fetchall()
        print("module_id:",data[0][0])
        print("num_page:",data[0][1])
    return data[0][0], data[0][1]


def get_module_info(connection, module_id):
    """Obtains the module information from the database

    Args:
        connection (mysql.connector.connection.MySQLConnection): Connection to the database
        module_id (int): Module ID to obtain the module information

    Returns:
        A list with the module information
    """
    query = "SELECT file_path FROM modules WHERE id = {}".format(module_id)
    with connection.cursor() as cursor:
        cursor.execute(query)
        data = cursor.fetchall()
        json_name = data[0][0]
        print("file_path:",json_name)
        info = json_name.split("_")
        dir, company, word_size = info[:-2], info[-2], (info[-1])[:-5]
        dir = "_".join(dir)
        print("dir:",dir)
        print("company:",company)
        print("word_size:",word_size)
    return dir, get_subdir_os(company+word_size)


def get_subdir_os(cpu):
    """Obtains the subdirectory of the OS

    Args:
        cpu (str): CPU of the OS

    Returns:
        A string with the subdirectory of the OS
    """
    if cpu == "Intel32":
        return "32-bits"
    elif cpu == "Intel64":
        return "64-bits"
    # XXX To be updated when new archs are considered
    else:
        return "" # To search in all subdirectories


if __name__ == "__main__":
    #Check argparse description
    parser = argparse.ArgumentParser(description="A Python script to extract a page from its module")
    parser.add_argument("-folder", "--folder",help="Folder where ZIP files are located",metavar="folder", default="/mnt/modules-Windows/")
    parser.add_argument("-sumdir", "--sumdir", help="Folder where sum.py script is located", metavar="sumdir", default="../similarity-unrelocated-module")
    parser.add_argument("page_id",help="Page ID to extract",metavar="page_id",type=int)
    parser.add_argument("-lv","--loggerlevel",help="Set the default level for logger.\
        The default level is logging.WARNING",metavar='',default=logging.WARNING,type=int,\
        choices=[logging.NOTSET,logging.DEBUG,logging.INFO,logging.WARNING,logging.ERROR,logging.CRITICAL])
    parser.add_argument("-tpdir","--temporarydirectory",help="Temporary directory where .dmp files will be stored",default=gettempdir())
    parser.add_argument("-vbf","--verbosefails",help="Show additional information about extracting zips",default=False,action="store_true")
    parser.add_argument("-cfg", "--configfile", help="Specify path to config file.\
        The default path is filepaths.ini on this folder", metavar='', default="config.ini")
    
    args = parser.parse_args()
    t1 = datetime.now()
    t1s = t1.strftime("%H:%M:%S")
    print("[+] Staring execution at {}".format(t1s))

    print("[+] Creating logger ..."),
    logger = create_logger(args.loggerlevel)
    print("done!")
    zpfolder = args.folder

    if not os.path.isdir(zpfolder):
        logger.error("Folder does not exist")
        print("Exiting script...")
        sys.exit(-1)

    page_id = args.page_id
    cfg_path = args.configfile
    host_g, user_g, pwd_g, dbname_g = read_config(cfg_path)

    try:
        print("[+] Adding {} to Python syspath...".format(args.sumdir)),
        sys.path.append(os.path.abspath(args.sumdir))
        print("done!")
        print("[+] Trying to import sum.py..."),
        aux = args.sumdir
        import sum
        print("done!")

        print("[+] Logging in {} as {} to use {} database".format(host_g, user_g, dbname_g))
        with connect(host=host_g, user=user_g, password=pwd_g, database=dbname_g) as connection_g:
            print("done!")
            print("[+] Obtaining the module_id and num_page of the page..."),
            module_id, num_page = get_page_info(connection_g, page_id)
            print("done!")
            dir, subdir = get_module_info(connection_g, module_id)
            zpfiles = get_all_file_paths(zpfolder+subdir,".zip")

            print("[+] Creating temporary directory..."),
            tpf = mkdtemp(dir=args.temporarydirectory)
            print("done!")

            err, correct, total = extract_zip(zpfiles,tpf,args.derelocation, dir, num_page, page_id)
            print("err:",err)
            print("found pages:",correct)
            print("total:",total)
            print("[+] Deleting temporary directory..."),
            #In case folder can't be deleted due to permissions
            if not os.access(tpf,os.W_OK):
                logger.debug("Changing folder permissions")
                os.chmod(path, stat.S_IWUSR)
            shutil.rmtree(os.path.abspath(tpf))
            print("done!")

            if args.verbosefails:
                print("[+] Showing failed ZIPS")
                for error in err:
                    logger.error("Cant process {} due to exception {}".format(error[0],error[1]))
                for zips in wrong_zips:
                    print(zips)
            print("Correctly processed ZIP files {}".format(correct))
            print("Total ZIP files processed {}".format(total))
            t2 = datetime.now()
            t2s = t2.strftime("%H:%M:%S")
            print("Ending execution at {}".format(t2s))
            tt = t2 - t1
            ts = int(tt.total_seconds())
            print("Total running time {} seconds".format(ts))
        
    except Exception as e:
        print(e)
        import traceback
        traceback.print_exc()
        exit(-1)
        