# Description: This script is used to plot the results of the test_hashes.py script.
# Phase: Análisis
# Author: Luis Palazón Simón

import pandas as pd
import matplotlib.pyplot as plt

# Name of the file with the results of the test_hashes.py script
FILE = 'go_test_hashes.txt'

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

def read_test_hashes(file):
    with open(file, 'r') as f:
        lines = f.readlines()
    data = []
    for i in range(0, len(lines), 4):
        # Test $i
        test = lines[i].split()[1]
        # SDHash equal: $x of 282
        sdhash = int(lines[i+1].split()[2])*100/282
        # TLSH equal: $y of 282
        tlsh = int(lines[i+2].split()[2])*100/282
        # SSDeep equal: $z of 282
        ssdeep = int(lines[i+3].split()[2])*100/282
        data.append([test, sdhash, tlsh, ssdeep])
    df = pd.DataFrame(data, columns=['Test', 'SDHASH', 'TLSH', 'SSDEEP'])
    return df

if __name__ == '__main__':
    df = read_test_hashes(FILE)
    df.plot(x='Test', y=['SDHASH', 'TLSH', 'SSDEEP'], kind='line')
    plt.xlabel('Número de bytes cambiados', fontname='TeX Gyre Pagella')
    plt.ylabel('Porcentaje de colisiones', fontname='TeX Gyre Pagella')
    plt.title('Porcentaje de colisiones en función del número de bytes cambiados')
    xs = range(256, 2049, 256)
    xs = [1] + list(xs)
    xs_txt = ['{}'.format(x) for x in xs]
    ys = range(0, 101, 10)
    ys_txt = ['{}\%'.format(y) for y in ys]
    plt.xticks(xs, xs_txt)
    plt.yticks(ys, ys_txt)
    plt.legend([r'\texttt{sdhash}', r'\texttt{TLSH', r'\texttt{ssdeep}'])
    plt.show()