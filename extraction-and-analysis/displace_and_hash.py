# Description: Script to displace the pages and calculate the hashes of the 
#              pages after the displacement automatically. In addition, it
#              generates the byte distribution graphs of the pages before and
#              after the displacement.
# Phase: Analysis
# Author: Luis Palazón Simón

import pandas as pd
import matplotlib.pyplot as plt
import subprocess
from cmp_pages import mainRetDesc

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

# Directory where the byte distribution graphs and hashes will be saved
DIR = '../auto/'

file_path = './output_collisions_raw_dataset_filtered_2.out'
# line format of the file:
# CRITICAL:datalayer.database.page: [-] TLSH COLLISION [#pages 228438:228442]

df = pd.DataFrame(columns=['hash_function', 'page1', 'page2'])

with open(file_path, 'r') as file:
    for line in file:
        if "COLLISION" in line:
            # select the part of the line after '[-] '
            l = line.split('[-] ')[1]
            hash_function = l.split()[0]
            # select the part of the line after '#pages '
            l2 = l.split('#pages ')[1]
            l2 = l2[:-2] # remove ']'
            page1 = l2.split(':')[0]
            page2 = l2.split(':')[1]
            # print(hash_function, page1, page2)
            df = df._append({'hash_function': hash_function, 'page1': page1, 'page2': page2}, ignore_index=True)

    file.close()

# Group by page1 and page2 and concatenate the values of hash_function with the delimiter "+"
df = df.groupby(['page1', 'page2']).agg({'hash_function': '+'.join}).reset_index()

## PAGE ANALYSIS ##
# Add a new column to the dataframe with the description of the collision
df['desc'] = ''
# Recorrer las filas del dataframe
for index, row in df.iterrows():
    # Obtener los números de página
    page1 = row['page1']
    page2 = row['page2']
    df.at[index, 'desc'] = mainRetDesc(page1, page2)

## COLLISION FILTERING ##
# Remove the rows that have the field 'desc' a text that contains 'Error'
# There are errors for 4 collisions of empty pages, so we remove them
df = df[~df['desc'].str.contains('Error')]
# Remove the rows that have the field 'desc' a text that contains '\Delta = 0'
# The entries are equal so it does not make sense to analyze the collision
df = df[~df['desc'].str.contains('\Delta = 0')]

# Let only the first row of a same page1
df = df.drop_duplicates(subset='page1', keep='first')

# Save the dataframe to an excel file
df.to_excel('coll_analisis_filter.xlsx', index=False)

## HASHES CALCULATION ##
i = 0
for index, row in df.iterrows():
    # 'desc' format: "desplazamiento de %x%B (%y%)"
    if 'desplazamiento de' in row['desc']:
        # Obtain the number of displacement bytes
        slide = row['desc'].split()[2][:-1]
        # Obtain if the slide is in the first or second slide
        slide_page = row['desc'].split()[3][1:-1]
        slide_page = int(slide_page)
        slide_page = "--slide1" if slide_page == 1 else "--slide2"
        # Obtaining the page numbers
        page1 = row['page1']
        page2 = row['page2']
        # Obtaining the byte distribution graphs
        subprocess.run(["python", "dist_bytes.py", page1, page2], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["python", "dist_bytes.py", page1, page2, slide_page, slide], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print('Byte distribution graphs created for pages {} and {}'.format(page1, page2))
        # Calculate the hashes
        with open(DIR+page1+'_'+page2+'/hashes_results.txt', 'w') as output_file: # write mode
            output_file.write('Tipo de colisión original detectada: {}\n'.format(row['hash_function']))
            output_file.write('Caso de estudio: {}\n'.format(row['desc']))
        output_file.close()
        with open(DIR+page1+'_'+page2+'/hashes_results.txt', 'a') as output_file: # append mode
            subprocess.run(["python2", "hashes.py", page1, "-page2", page2, slide_page, slide, "-prefixAA"], stdout=output_file, stderr=subprocess.DEVNULL)
        output_file.close()
        print('Hashes calculated for pages {} and {}'.format(page1, page2))
        i += 1
        print('Collisions analyzed: {}'.format(i))
    