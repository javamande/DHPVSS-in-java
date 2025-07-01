import pandas as pd
import matplotlib.pyplot as plt
data = {
    'n': [10, 20, 40, 80, 160],
    'Sharing_mean': [0.139, 0.202, 0.528, 1.501, 5.027],
    'Sharing_std': [0.119, 0.138, 0.292, 0.258, 0.383],
}
df = pd.DataFrame(data)

plt.figure(figsize=(7, 4))
plt.errorbar(
    df['n'],
    df['Sharing_mean'],
    yerr=df['Sharing_std'],
    fmt='-o',
    capsize=5,
    markersize=8,
    label='Sharing Phase'
)
plt.title('Sharing Phase Runtime vs. Number of Parties')
plt.xlabel('Number of Parties ($n$)')
plt.ylabel('Time (seconds)')
plt.xticks(df['n'])
plt.grid(True, linestyle='--', alpha=0.7)
plt.legend()
plt.tight_layout()
plt.show()
