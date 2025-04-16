package org.example.pvss;

import java.math.BigInteger;

/**
 * Utility methods for the DHPVSS protocol.
 *
 * In our scheme, many operations (such as the SCRAPE test) are carried out in
 * the base field
 * of the elliptic curve. For an EC-based PVSS implementation, the elliptic
 * curve group parameters
 * (p, G, etc.) come from a standard curve (e.g. secp256r1). Here, p is the
 * characteristic of the field,
 * and the arithmetic for the dual‐code coefficients and other values is
 * performed modulo p.
 *
 * The SCRAPE coefficients are computed as follows:
 * For each participant i ∈ {1,…, n}, we define:
 *
 * coeff_i = ∏₍ⱼ=₁, j≠i₎^n (α_i – α_j)⁻¹ (mod p)
 *
 * which are used later, for example, to verify the consistency of distributed
 * shares.
 */
public class DhPvssUtils {

    /**
     * Precompute an inverse table for values in the range [–(n–1), …, n–1] modulo
     * primeOrder.
     * We allocate an array of length 2*n so that the index mapping is:
     * index = i corresponds to the value (i – (n–1)) mod primeOrder.
     *
     * @param groupParams the group parameters (EC base field’s prime, etc.)
     * @param n           the number of participants.
     * @return an array of BigInteger containing the modular inverses for the
     *         required range.
     */
    public static BigInteger[] precomputeInverseTable(GroupGenerator.GroupParameters groupParams, int n) {
        // Retrieve the prime modulus of the underlying field from the EC parameters.
        BigInteger primeOrder = groupParams.getgroupOrd();

        // Allocate an array of length 2*n.
        BigInteger[] inverseTable = new BigInteger[2 * n];

        // Compute the starting value a = (1 - n) mod primeOrder.
        BigInteger a = BigInteger.valueOf(1 - n).mod(primeOrder);
        BigInteger one = BigInteger.ONE;

        // For each i from 0 to 2*n - 1:
        // Compute the modular inverse of a (if a ≠ 0), then increment a by 1 modulo
        // primeOrder.
        for (int i = 0; i < 2 * n; i++) {
            if (a.equals(BigInteger.ZERO)) {
                // If a is zero, it has no modular inverse; we store null (or choose an
                // alternative handling).
                inverseTable[i] = null;
            } else {
                inverseTable[i] = a.modInverse(primeOrder);
            }
            // Increase a by 1 modulo primeOrder.
            a = a.add(one).mod(primeOrder);
        }
        return inverseTable;
    }

    /**
     * Derives SCRAPE coefficients (for the dual-code test) for participant indices
     * 1 to n.
     *
     * For each participant i ∈ {1,…, n}, we compute:
     * coeff_i = ∏ (α_i − α_j)⁻¹, j ∈ {1,…, n} and j ≠ i,
     * modulo the prime modulus. These coefficients are used later in the protocol
     * to “weight”
     * the shares for consistency checks.
     *
     * @param groupParams  the EC group parameters (contains the prime modulus).
     * @param from         the starting index (should be 1 since we compute for
     *                     indices 1 to n).
     * @param n            the number of participants.
     * @param inverseTable the precomputed inverses for the range [–(n–1), …, n–1]
     *                     modulo p.
     * @param alphas       the array of evaluation points (α₀, α₁, …, αₙ) associated
     *                     with participants.
     * @return an array of SCRAPE coefficients (one for each participant index from
     *         1 to n).
     */
    public static BigInteger[] deriveScrapeCoeffs(GroupGenerator.GroupParameters groupParams, int from, int n,
            BigInteger[] inverseTable, BigInteger[] alphas) {
        BigInteger primeOrder = groupParams.getgroupOrd();
        BigInteger[] coeffs = new BigInteger[n];
        // System.out.println("=== INVERSE TABLE DEBUG ===");
        for (int i = 1; i <= n; i++) {
            BigInteger coeff = BigInteger.ONE;
            for (int j = from; j <= n; j++) {
                if (i == j) {
                    continue; // Skip when the indices are equal.
                }
                // The difference between evaluation points is (α_i - α_j).
                // Map this difference to an index in the inverse table.
                int index = (i - j) + (n - 1);
                if (index < 0 || index >= inverseTable.length) {
                    throw new IllegalArgumentException("bad index " + index);
                }
                coeff = coeff.multiply(inverseTable[index]).mod(primeOrder);
                // System.out.println("For i = " + i + ", j = " + j +
                // ": diff = " + (i - j) + ", index = " + index +
                // ", inverse = " + inverseTable[index]);
            }
            coeffs[i - 1] = coeff;
        }
        System.out.println(" ");
        return coeffs;
    }

    /**
     * Derives the dual-code coefficients (vPrimes) for indices 0 to n.
     *
     * We want vPrimes to be an array of length n+1, where:
     * - vPrimes[0] = 1 (by convention), and
     * - for i = 1..n, vPrimes[i] = corresponding SCRAPE coefficient computed above.
     *
     * @param groupParams  the EC group parameters.
     * @param n            the number of participants.
     * @param inverseTable the precomputed inverse table.
     * @param alphas       the array of evaluation points.
     * @return an array of dual-code coefficients of length n+1.
     */
    public static BigInteger[] deriveScrapeCoeffsForVPrimes(GroupGenerator.GroupParameters groupParams, int n,
            BigInteger[] inverseTable, BigInteger[] alphas) {
        // First compute the SCRAPE coefficients for indices 1..n.
        BigInteger[] temp = deriveScrapeCoeffs(groupParams, 1, n, inverseTable, alphas);

        // Allocate an array of length n+1.
        BigInteger[] result = new BigInteger[n + 1];

        // Set the 0th coefficient to 1 by convention.
        result[0] = BigInteger.ONE;

        // Copy the computed SCRAPE coefficients into positions 1..n.
        System.arraycopy(temp, 0, result, 1, n);

        return result;
    }

}
