import pandas as pd
import matplotlib.pyplot as plt

data = {
    'n': [10, 20, 40, 80, 160],
    'Verification_mean': [2.585, 7.544, 28.054, 167.104, 1380.271],
    'Verification_std': [0.608, 1.163, 1.185, 21.141, 25.396],
}
df = pd.DataFrame(data)

plt.figure(figsize=(7, 4))
plt.errorbar(
    df['n'],
    df['Verification_mean'],
    yerr=df['Verification_std'],
    fmt='-o',
    capsize=5,
    markersize=8,
    label='Verification Phase'
)
plt.title('Verification Phase Runtime vs. Number of Parties')
plt.xlabel('Number of Parties ($n$)')
plt.ylabel('Time (seconds)')
plt.xticks(df['n'])
plt.grid(True, linestyle='--', alpha=0.7)
plt.legend()
plt.tight_layout()
plt.show()
