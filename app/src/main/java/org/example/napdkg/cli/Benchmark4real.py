import pandas as pd
import matplotlib.pyplot as plt

data = {
    'n': [10, 20, 40, 80, 160],
    'Setup_mean': [1.270, 2.720, 5.867, 12.463, 29.357],
    'Setup_std': [0.156, 0.233, 0.173, 0.355, 0.595],
    'Sharing_mean': [0.139, 0.202, 0.528, 1.501, 5.027],
    'Sharing_std': [0.119, 0.138, 0.292, 0.258, 0.383],
    'Verification_mean': [2.585, 7.544, 28.054, 167.104, 1380.271],
    'Verification_std': [0.608, 1.163, 1.185, 21.141, 25.396],
    'Threshold_mean': [0.043, 0.045, 0.087, 0.241, 1.692],
    'Threshold_std': [0.031, 0.050, 0.050, 0.064, 0.132],
    'Total_mean': [4.158, 10.652, 34.764, 181.826, 1419.426],
    'Total_std': [1.026, 1.702, 1.650, 20.756, 25.754]
}
df = pd.DataFrame(data)

phases = ['Setup', 'Sharing', 'Verification', 'Threshold', 'Total']

plt.figure(figsize=(12, 7))
for phase in phases:
    plt.errorbar(
        df['n'],
        df[f'{phase}_mean'],
        yerr=df[f'{phase}_std'],
        fmt='-o',
        capsize=5,
        markersize=8,
        label=phase
    )

plt.title("NAP-DKG Benchmark: Phase Timing vs. Number of Parties")
plt.xlabel("Number of Parties ($n$)")
plt.ylabel("Time (seconds)")
plt.xticks(df['n'])
plt.grid(True, linestyle='--', alpha=0.7)
plt.legend()
plt.tight_layout()
plt.show()
