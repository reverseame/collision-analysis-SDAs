# Description: Script to generate a dataframe with the results of the analysis 
#              after the sliding method has been applied.
# Phase: Analysis
# Author: Luis Palazón Simón

import pandas as pd
import os
import matplotlib.pyplot as plt

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
    "figure.figsize": (24, 8)
})

# Directory where the byte distribution graphs and hashes have been saved
DIR = './auto/'

# DIR contains subdirectories with name X_Y, where X is the page number of the 
# first file and Y is the page number of the second file. These subdirectories 
# contain some .png with graphs and a file called hashes_results.txt
# The hashes_results.txt file has the following format:
# Original collision type detected: *hash_function*
# Case study: *desc*
# More information about the case study...

# Create a dataframe with the columns page1, page2, hash_function, desc and new_hash_function
df = pd.DataFrame(columns=['page1', 'page2', 'hash_function', 'desc', 'new_hash_function'])

for subdir in os.listdir(DIR):
    for file in os.listdir(DIR+subdir):
        if file == 'hashes_results.txt':
            with open(DIR+subdir+'/'+file, 'r') as f:
                content = f.readlines()
                page1 = int(subdir.split('_')[0])
                page2 = int(subdir.split('_')[1])
                hash_function = content[0].split(': ')[1].strip()
                desc = content[1].split(': ')[1].strip()

                new_hash_function = ''
                if any('Hashes for algorithm TLSH are equal' in line for line in content):
                    new_hash_function += 'TLSH'
                if any('Hashes for algorithm SDHash are equal' in line for line in content):
                    if new_hash_function != '':
                        new_hash_function += '+'
                    new_hash_function += 'SDHASH'
                if any('Hashes for algorithm SSDeep are equal' in line for line in content):
                    if new_hash_function != '':
                        new_hash_function += '+'
                    new_hash_function += 'SSDEEP'
                    
                # Add a new row to the dataframe with the results
                df = df._append({'page1': page1, 'page2': page2, 'hash_function': hash_function, 'desc': desc, 'new_hash_function': new_hash_function}, ignore_index=True)
            f.close()

# Save the dataframe to an Excel file
df.to_excel('analysis_results.xlsx', index=False)

# Show the frequency of the values of the new_hash_function column
print(df['new_hash_function'].value_counts())

## HISTOGRAMS ##
df['desc'] = df['desc'].str.replace('desplazamiento de ', '', regex=True)
df['desc'] = r'$\Delta$ = ' + df['desc']
df['desc'] = df['desc'].str.replace(r'\([^)]*\)', '', regex=True)
df['desc'] = df['desc'].str.replace(r' \+ 0B diferentes', '', regex=True)

# Show the frequency of the values of the field 'desc' for each value of 'new_hash_function'
for value in df['new_hash_function'].unique():
    df['desc'][df['new_hash_function'] == value].value_counts().plot(kind='bar')
    if value == '':
        plt.title('Frecuencia de las causas de colisión original sin conseguir nueva colisión al desplazar')
    else:
        plt.title('Frecuencia de las causas de colisión original para nuevas colisiones '+value)
    plt.xlabel('Causas de colisión original')
    plt.ylabel('Frecuencia')
    plt.show()

# Histogram that represents the frequency of the values of the 'desc' field for the cases in which 'SDHASH' in new_hash_function
df['desc'][df['new_hash_function'].str.contains('SDHASH')].value_counts().plot(kind='bar')
plt.title('Frecuencia de las causas de colisión original para nuevas colisiones SDHASH')
plt.xlabel('Bytes desplazados')
plt.ylabel('Frecuencia')
plt.show()

# Histogram that represents the frequency of the values of the 'desc' field for the cases in which 'SSDEEP' in new_hash_function
df['desc'][df['new_hash_function'].str.contains('SSDEEP')].value_counts().plot(kind='bar')
plt.title('Frecuencia de las causas de colisión original para nuevas colisiones SSDEEP')
plt.xlabel('Causas de colisión original')
plt.ylabel('Frecuencia')
plt.show()

# Histogram that represents the frequency of the values of the 'desc' field for the cases in which 'TLSH' in new_hash_function
df['desc'][df['new_hash_function'].str.contains('TLSH')].value_counts().plot(kind='bar')
plt.title('Frecuencia de las causas de colisión original para nuevas colisiones TLSH')
plt.xlabel('Causas de colisión original')
plt.ylabel('Frecuencia')
plt.show()

# Histogram that represents the frequency of the values of the 'desc' field for the cases in which 'TLSH+SDHASH' in new_hash_function
df['desc'][df['new_hash_function'] == ''].value_counts().plot(kind='bar')
plt.title('Frecuencia de las causas de colisión original sin conseguir nueva colisión al desplazar')
plt.xlabel('Causas de colisión original')
plt.ylabel('Frecuencia')
plt.show()

# More information about the new_hash_function field
pd.set_option('display.max_rows', None)
print("Nuevas colisiones TLSH:")
print(df[df['new_hash_function'].str.contains('TLSH')])
print(df[df['new_hash_function'].str.contains('TLSH')].shape[0])
print("Nuevas colisiones SDHASH:")
print(df[df['new_hash_function'].str.contains('SDHASH')])
print(df[df['new_hash_function'].str.contains('SDHASH')].shape[0])
print("Nuevas colisiones SSDEEP:")
print(df[df['new_hash_function'].str.contains('SSDEEP')])
print(df[df['new_hash_function'].str.contains('SSDEEP')].shape[0])
print("Colisiones originales sin conseguir nueva colisión al desplazar:")
print(df.loc[df['new_hash_function'] == ''])
print(df.loc[df['new_hash_function'] == ''].shape[0])

print("Total de colisiones: ", df.shape[0])
print("Total de colisiones TLSH: ", df.loc[df['new_hash_function']=='TLSH'].shape[0])
print("Total de colisiones SDHASH: ", df.loc[df['new_hash_function']=='SDHASH'].shape[0])
print("Total de colisiones SSDEEP: ", df.loc[df['new_hash_function']=='SSDEEP'].shape[0])
print("Total de colisiones TLSH+SDHASH: ", df.loc[df['new_hash_function']=='TLSH+SDHASH'].shape[0])
print("Total de colisiones TLSH+SSDEEP: ", df.loc[df['new_hash_function']=='TLSH+SSDEEP'].shape[0])
print("Total de colisiones SDHASH+SSDEEP: ", df.loc[df['new_hash_function']=='SDHASH+SSDEEP'].shape[0])
print("Total de colisiones TLSH+SDHASH+SSDEEP: ", df.loc[df['new_hash_function']=='TLSH+SDHASH+SSDEEP'].shape[0])