import pandas as pd
import matplotlib.pyplot as plt

# Construct the DataFrame with the provided benchmarking data (in ms)
data = {
    'n': [20, 40, 80],
    'Setup_mean': [2717.513, 5806.647, 12417.154],
    'Setup_stddev': [170.834, 166.744, 300.925],
    'Sharing_mean': [664.300, 1786.328, 5784.113],
    'Sharing_stddev': [109.939, 235.486, 703.209],
    'Verification_mean': [35247.322, 134484.992, 642949.496],
    'Verification_stddev': [442.954, 1116.911, 5222.365],
    'Threshold_mean': [4442.225, 19277.953, 114115.873],
    'Threshold_stddev': [442.780, 777.000, 4249.395],
    'Total_mean': [43071.679, 161356.308, 775267.213],
    'Total_stddev': [458.559, 1264.258, 8794.291]
}
df = pd.DataFrame(data)

# Convert times from milliseconds to seconds
time_cols = [col for col in df.columns if col != 'n']
df[time_cols] = df[time_cols] / 1000.0

# Plot curves with error bars for each phase, in seconds
plt.figure(figsize=(12, 7))

phases = ['Setup', 'Sharing', 'Verification', 'Threshold', 'Total']
for phase in phases:
    plt.errorbar(
        df['n'],
        df[f'{phase}_mean'],
        yerr=df[f'{phase}_stddev'],
        fmt='-o',
        capsize=5,
        markersize=8,
        label=phase
    )

plt.title("NAP-DKG Benchmark Scaling Curve")
plt.xlabel("Number of Parties (n)")
plt.ylabel("Time (s)")
plt.xticks(df['n'])
plt.grid(True, linestyle='--', alpha=0.7)
plt.legend()
plt.tight_layout()
plt.show()
