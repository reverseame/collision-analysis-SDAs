import seaborn as sns
import matplotlib.pyplot as plt
import json
import sys
import numpy as np


# Configuración para usar LaTeX en Matplotlib
plt.rcParams.update({
    "text.usetex": True,
    "font.family": "serif",
    "font.serif": ["Times"],
    "font.sans-serif": ["Computer Modern Sans serif"],
    "font.monospace": ["Computer Modern Typewriter"],
    "axes.labelsize": 18,
    "font.size": 18,
    "legend.fontsize": 18,
    "xtick.labelsize": 14,
    "ytick.labelsize": 14,
    "figure.figsize": (48, 30),
})

# Cargar datos desde el archivo JSON
with open(sys.argv[1], 'r') as file:
    data = json.load(file)

# Extraer los datos de los tamaños de los bloques para cada sección
sizes_q0 = data['sizes_counter_q0']
sizes_q1 = data['sizes_counter_q1']
sizes_q2 = data['sizes_counter_q2']
sizes_q3 = data['sizes_counter_q3']
sizes_q4 = data['sizes_counter_q4']

# Crear una lista con los tamaños de bloques para cada sección, repitiendo los tamaños según su frecuencia
sizes_list_q0 = [int(size) for size, count in sizes_q0.items() for _ in range(count)]
sizes_list_q1 = [int(size) for size, count in sizes_q1.items() for _ in range(count)]
sizes_list_q2 = [int(size) for size, count in sizes_q2.items() for _ in range(count)]
sizes_list_q3 = [int(size) for size, count in sizes_q3.items() for _ in range(count)]
sizes_list_q4 = [int(size) for size, count in sizes_q4.items() for _ in range(count)]

sections = ['Q1', 'Q2', 'Q3', 'Q4']

# Agrupar los tamaños de los bloques de cada sección en listas separadas
all_sizes = [sizes_list_q1, sizes_list_q2, sizes_list_q3, sizes_list_q4]
#sections = ['Primer cuarto', 'Segundo cuarto', 'Tercer cuarto', 'Cuarto cuarto']

all_sizes_flat = sizes_list_q1 + sizes_list_q2 + sizes_list_q3 + sizes_list_q4
quarters = (
            ['First quarter'] * len(sizes_list_q1) +
            ['Second quarter'] * len(sizes_list_q2) +
            ['Third quarter'] * len(sizes_list_q3) +
            ['Fourth quarter'] * len(sizes_list_q4))

# Crear el gráfico de violín
plt.figure(figsize=(10, 6))
sns.violinplot(x=quarters, y=all_sizes_flat, hue=quarters, legend=False)
#plt.yscale('log')
# plt.xlabel('Null block size (bytes)')
plt.xlabel('Page quarter in which the null block starts')
# plt.ylabel('Frequency')
plt.ylabel('Null block size (bytes)')
#plt.legend()
plt.tight_layout()
#plt.show()
plt.savefig('violin_plots.pdf', format='pdf')
#plt.savefig('violin_plots.png', format='png')
