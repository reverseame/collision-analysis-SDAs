# Description: Script to read the output file of APOTHEOSIS and extract the pages that have to be examined.
# Phase: Extraction
# Author: Luis Palazón Simón

import pandas as pd
import matplotlib.pyplot as plt
import subprocess

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

# Save the dataframe to an excel file
# df.to_excel('coll_dataset.xlsx', index=False)

## EXTRACCIÓN DE PÁGINAS A EXAMINAR ##
# Initialize the set of pages to examine
pages_to_examine = set()

# Add the pages to examine to the set
for page in df['page1']:
    pages_to_examine.add(page)
for page in df['page2']:
    pages_to_examine.add(page)
print(len(pages_to_examine))

# Extract the pages to examine
total = 0
for page in pages_to_examine:
    subprocess.run(["python2", "extract.py", page], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    total += 1
    print('Page {} extracted. Total: {}'.format(page, total))