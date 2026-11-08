import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

# Author: Luis Palazón Simón

import pandas as pd
import matplotlib.pyplot as plt

plt.rcParams.update({
    "text.usetex": True,
    "font.family": "serif",
    "font.serif": ["Times"],
    "font.sans-serif": ["Computer Modern Sans serif"],
    "font.monospace": ["Computer Modern Typewriter"],
    "axes.labelsize": 18,
    "font.size": 16,
    "legend.fontsize": 16,
    "xtick.labelsize": 16,
    "ytick.labelsize": 16,
    "figure.figsize": (24, 12),
})

# Cargar el dataframe desde un fichero excel
df = pd.read_excel('coll_analisis_filtrado.xlsx')

# # Traducir el campo 'desc' a inglés reemplazando los 'diferentes' contenidos en el texto por 'different'
# df['desc'] = df['desc'].str.replace('diferentes', 'different')

## HISTOGRAMA DE LAS CAUSAS DE COLISIÓN ##
# Borrar en el campo 'desc' el texto que contienen los paréntesis (incluyendo los propios paréntesis)
df['desc'] = df['desc'].str.replace(r'\([^)]*\)', '', regex=True)
# Borrar del campo desc el texto ' + 0B diferentes' en caso de que aparezca
df['desc'] = df['desc'].str.replace(r' \& 0B diferentes', '', regex=True)

# Histograma apilado para TLSH, SDHASH y SSDEEP
# Obtener los conteos para cada hash function
tls_counts = df['desc'][df['hash_function'].str.contains('TLSH')].value_counts()
sdhash_counts = df['desc'][df['hash_function'].str.contains('SDHASH')].value_counts()
ssdeep_counts = df['desc'][df['hash_function'].str.contains('SSDEEP')].value_counts()
# Unificar las claves (causas de colisión) para que los histogramas tengan las mismas barras
causas_comunes = list(set(tls_counts.index).union(set(sdhash_counts.index)).union(set(ssdeep_counts.index)))
# Crear DataFrame con los datos
data = pd.DataFrame({
    r'\texttt{TLSH}': tls_counts.reindex(causas_comunes, fill_value=0),
    r'\texttt{sdhash}': sdhash_counts.reindex(causas_comunes, fill_value=0),
    r'\texttt{ssdeep}': ssdeep_counts.reindex(causas_comunes, fill_value=0)
})
# Suscribir en la columna desc de data la palabra '+' por '&'
data.index = data.index.str.replace('+', '\&')
data.index = data.index.str.replace('diferentes', 'with variations')
data.index = data.index.str.replace('desplazamiento de', 'offset of')

# Ordenar las filas de data por la suma de las columnas
data = data.loc[data.sum(axis=1).sort_values(ascending=False).index]

# Crear el heatmap
sns.heatmap(data, yticklabels=True, annot=True, fmt='d', cmap='viridis', cbar=True)
plt.ylabel('Collision cause')
plt.xlabel('Hash function')
plt.gcf().set_size_inches(10, 14)
plt.tight_layout()
# plt.show()
plt.savefig('heatmap2.pdf', format='pdf')
