package org.example.napdkg.util;

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
     * r_i = v_i · m*(α_i) (mod p).
     *
     * @param p subgroup order (prime modulus)
     * @param α evaluation points [0..n], we only use α[1..n]
     * @param v dual‐code coefficients [v1..vn]
     * @param c polynomial coefficients [c0..c_{n−t−1}] of m*(X)
     * @param n total number of participants
     * @return array r[0..n−1], where r[i] = v_{i+1}·m*(α_{i+1}) (mod p)
     */
    public static BigInteger[] computeScrapeWeights(
            BigInteger p,
            BigInteger[] α,
            BigInteger[] v,
            BigInteger[] c,
            int n) {
        BigInteger[] r = new BigInteger[n];
        for (int i = 1; i <= n; i++) {
            // 1) evaluate m*(α[i]) = c₀ + c₁·α[i] + c₂·α[i]^2 + … (mod p)
            BigInteger eval = BigInteger.ZERO;
            BigInteger xPow = BigInteger.ONE; // α[i]^0
            for (int k = 0; k < c.length; k++) {
                eval = eval.add(c[k].multiply(xPow)).mod(p);
                xPow = xPow.multiply(α[i]).mod(p);
            }
            // 2) multiply by dual‐code coefficient v[i−1]
            r[i - 1] = v[i - 1].multiply(eval).mod(p);
        }
        return r;
    }

    /**
     * Simple SCRAPE dual‐code weights:
     *
     * v_j = ∏_{k=1, k≠j}^n (α[j] - α[k])^{-1} (mod p),
     * for j=1..n.
     *
     * @param p      prime modulus
     * @param alphas array of length (n+1), where alphas[0]=0 unused, and
     *               alphas[1..n] are distinct
     * @param n      total number of participants
     * @return BigInteger[n] = { v₁, v₂, …, vₙ } (zero‐based array)
     */
    public static BigInteger[] deriveShrapeCoeffs(
            BigInteger p,
            BigInteger[] alphas,
            int n) {
        BigInteger[] v = new BigInteger[n];
        for (int j = 1; j <= n; j++) {
            BigInteger prod = BigInteger.ONE;
            for (int k = 1; k <= n; k++) {
                if (j == k)
                    continue;
                // diff = α[j] - α[k] (mod p)
                BigInteger diff = alphas[j].subtract(alphas[k]).mod(p);
                // invert mod p
                BigInteger inv = diff.modInverse(p);
                prod = prod.multiply(inv).mod(p);
            }
            v[j - 1] = prod; // store into zero‐based array slot
        }
        return v;
    }

}
