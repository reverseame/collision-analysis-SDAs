# Description: Script to analyze the causes of the collisions and generate histograms with the results.
# Phase: Analysis
# Author: Luis Palazón Simón

import pandas as pd
import matplotlib.pyplot as plt
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
df.to_excel('coll_dataset.xlsx', index=False)

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

## HISTOGRAMAS DE LAS CAUSAS DE COLISIÓN ##
# Remove the text between parentheses in the field 'desc'
df['desc'] = df['desc'].str.replace(r'\([^)]*\)', '', regex=True)
# Remove the text ' + 0B diferentes' in the field 'desc'
df['desc'] = df['desc'].str.replace(r' \+ 0B diferentes', '', regex=True)

# General histogram
df['desc'].value_counts().plot(kind='bar')
plt.title('Frecuencia de las causas de colisión')
plt.xlabel('Causas de colisión')
plt.ylabel('Frecuencia')
plt.show()

# TLSH histogram (contains TLSH in the field hash_function)
df['desc'][df['hash_function'].str.contains('TLSH')].value_counts().plot(kind='bar')
plt.title(r'Frecuencia de las causas de colisión para \texttt{TLSH}')
plt.xlabel('Causas de colisión')
plt.ylabel('Frecuencia')
plt.show()

# SDHASH histogram (contains SDHASH in the field hash_function)
df['desc'][df['hash_function'].str.contains('SDHASH')].value_counts().plot(kind='bar')
plt.title(r'Frecuencia de las causas de colisión para \texttt{SDHASH}')
plt.xlabel('Causas de colisión')
plt.ylabel('Frecuencia')
plt.show()

# SSDEEP histogram (contains SSDEEP in the field hash_function)
df['desc'][df['hash_function'].str.contains('SSDEEP')].value_counts().plot(kind='bar')
plt.title(r'Frecuencia de las causas de colisión para \texttt{SSDEEP}')
plt.xlabel('Causas de colisión')
plt.ylabel('Frecuencia')
plt.show()

# TLSH histogram (only TLSH in the field hash_function)
df['desc'][df['hash_function'] == 'TLSH'].value_counts().plot(kind='bar')
plt.yticks(range(0, 20, 2))
plt.title(r'Frecuencia de las causas de colisión sólo para \texttt{TLSH}')
plt.xlabel('Causas de colisión')
plt.ylabel('Frecuencia')
plt.show()


# Show the frequency of each cause of collision
for text in df['desc'].unique():
    print(text)
    print('---------------------------')

print("Total de colisiones: ", df.shape[0])
print("Total de colisiones TLSH: ", df.loc[df['hash_function'] == 'TLSH'].shape[0])
print("Total de colisiones SDHASH: ", df.loc[df['hash_function'] == 'TLSH+SDHASH'].shape[0])
print("Total de colisiones SSDEEP: ", df.loc[df['hash_function'] == 'TLSH+SSDEEP'].shape[0])
    