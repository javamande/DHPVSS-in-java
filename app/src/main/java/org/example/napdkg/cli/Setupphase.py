import pandas as pd
import matplotlib.pyplot as plt

data = {
    'n': [10, 20, 40, 80, 160],
    'Setup_mean': [1.270, 2.720, 5.867, 12.463, 29.357],
    'Setup_std': [0.156, 0.233, 0.173, 0.355, 0.595],
}

df = pd.DataFrame(data)

plt.figure(figsize=(7, 4))
plt.errorbar(
    df['n'],
    df['Setup_mean'],
    yerr=df['Setup_std'],
    fmt='-o',
    capsize=5,
    markersize=8,
    label='Setup Phase'
)
plt.title('Setup Phase Runtime vs. Number of Parties')
plt.xlabel('Number of Parties ($n$)')
plt.ylabel('Time (seconds)')
plt.xticks(df['n'])
plt.grid(True, linestyle='--', alpha=0.7)
plt.legend()
plt.tight_layout()
plt.show()
