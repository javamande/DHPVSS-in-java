import pandas as pd
import matplotlib.pyplot as plt

data = {
    'n': [10, 20, 40, 80, 160],
    'Threshold_mean': [0.043, 0.045, 0.087, 0.241, 1.692],
    'Threshold_std': [0.031, 0.050, 0.050, 0.064, 0.132],
}
df = pd.DataFrame(data)

plt.figure(figsize=(7, 4))
plt.errorbar(
    df['n'],
    df['Threshold_mean'],
    yerr=df['Threshold_std'],
    fmt='-o',
    capsize=5,
    markersize=8,
    label='Threshold Phase'
)
plt.title('Threshold Phase Runtime vs. Number of Parties')
plt.xlabel('Number of Parties ($n$)')
plt.ylabel('Time (seconds)')
plt.xticks(df['n'])
plt.grid(True, linestyle='--', alpha=0.7)
plt.legend()
plt.tight_layout()
plt.show()
