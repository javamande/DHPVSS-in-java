package org.example.pvss;

import java.math.BigInteger;

/**
 * Utility routines for DHPVSS as in the YOLO‑YOSO paper.
 *
 * All finite‑field ops (e.g. SCRAPE dual‑code) are done over Zₚ,
 * where p is the order of the EC subgroup 𝔾 (generator G).
 *
 * In particular, for i∈[1..n] we compute the dual‑code (SCRAPE) weights
 * 
 * vᵢ = ∏_{j=1, j≠i}ⁿ (αᵢ − αⱼ)^(−1) mod p
 *
 * These vᵢ are used when aggregating shares for the consistency check.
 */
public class DhPvssUtils {

    /**
     * Precomputes inverses of all differences in [–(n−1)..(n−1)] mod p,
     * so that
     *
     * (αᵢ − αⱼ)^(−1) ≡ inverseTable[ (i−j)+(n−1) ]
     *
     * for i≠j ∈ [1..n].
     *
     * @param groupParams holds p = |𝔾|
     * @param n           total parties
     * @return array of length 2n such that index k ↦ (k−(n−1))^(−1) mod p
     */
    public static BigInteger[] precomputeInverseTable(GroupGenerator.GroupParameters groupParams, int n) {
        BigInteger p = groupParams.getgroupOrd();
        BigInteger[] inv = new BigInteger[2 * n];
        BigInteger x = BigInteger.valueOf(1 - n).mod(p);

        for (int k = 0; k < 2 * n; k++) {
            inv[k] = x.equals(BigInteger.ZERO) ? null : x.modInverse(p);
            x = x.add(BigInteger.ONE).mod(p);
        }
        return inv;
    }

    /**
     * Compute SCRAPE dual‑code coefficients {v₁,…,vₙ}:
     *
     * for each i=1..n:
     * vᵢ = ∏_{j=1, j≠i}ⁿ (αᵢ − αⱼ)^(−1) mod p
     *
     * @param groupParams  holds p = |𝔾|
     * @param n            total parties
     * @param inverseTable as from precomputeInverseTable()
     * @param alphas       public evaluation points α₀,…,αₙ
     * @return array [v₁,…,vₙ]
     */
    public static BigInteger[] deriveScrapeCoeffs(
            GroupGenerator.GroupParameters groupParams,
            int n,
            BigInteger[] inverseTable,
            BigInteger[] alphas) {

        BigInteger p = groupParams.getgroupOrd();
        BigInteger[] v = new BigInteger[n];

        for (int i = 1; i <= n; i++) {
            BigInteger prod = BigInteger.ONE;
            for (int j = 1; j <= n; j++) {
                if (i == j)
                    continue;
                int idx = (i - j) + (n - 1);
                prod = prod.multiply(inverseTable[idx]).mod(p);
            }
            v[i - 1] = prod;
        }
        return v;
    }

    /**
     * Build the extended dual‑code array v′ of length n+1:
     * v′₀ = 1, v′ᵢ = vᵢ for i=1..n.
     *
     * @param groupParams  holds p = |𝔾|
     * @param n            total parties
     * @param inverseTable as from precomputeInverseTable()
     * @param alphas       public evaluation points α₀,…,αₙ
     * @return array [v′₀,…,v′ₙ]
     */
    public static BigInteger[] deriveScrapeCoeffsForVPrimes(
            GroupGenerator.GroupParameters groupParams,
            int n,
            BigInteger[] inverseTable,
            BigInteger[] alphas) {

        BigInteger[] v = deriveScrapeCoeffs(groupParams, n, inverseTable, alphas);
        BigInteger[] vPrime = new BigInteger[n + 1];
        vPrime[0] = BigInteger.ONE;
        System.arraycopy(v, 0, vPrime, 1, n);
        return vPrime;
    }
}
