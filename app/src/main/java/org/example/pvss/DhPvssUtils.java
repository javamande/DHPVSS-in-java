package org.example.pvss;

import java.math.BigInteger;

import org.example.pvss.GroupGenerator.GroupParameters;

public class DhPvssUtils {

    /**
     * Precompute an inverse table for values in the range [ -n+1, n-1 ] modulo
     * modulus.
     * We allocate an array of length 2*n so that the index mapping:
     * index = i corresponds to the value (i - (n - 1)) mod modulus.
     *
     * @param groupParams the prime order/Modolus and the generator of the cyclic
     *                    subgroup (a primitive root modulo
     *                    p).
     * @param n           the number of participants.
     * @return an array of BigInteger containing the modular inverses for the
     *         required range.
     */
    public static BigInteger[] precomputeInverseTable(GroupParameters groupParams, int n) {
        // Retrieve the prime modulus from the group parameters.
        BigInteger primeOrder = groupParams.getP();

        // Allocate an array of length 2*n.
        BigInteger[] inverseTable = new BigInteger[2 * n];

        // Compute the starting value a = (1 - n) mod modulus.
        BigInteger a = BigInteger.valueOf(1 - n).mod(primeOrder);
        BigInteger one = BigInteger.ONE;

        // For each i from 0 to 2*n - 1, compute the modular inverse of a (if it
        // exists),
        // then increment a by one modulo modulus.
        for (int i = 0; i < 2 * n; i++) {
            if (a.equals(BigInteger.ZERO)) {
                // Zero has no modular inverse; we can store null or handle as needed.
                inverseTable[i] = null;
            } else {
                inverseTable[i] = a.modInverse(primeOrder);
            }
            // Increase a by 1 (mod modulus)
            a = a.add(one).mod(primeOrder);
        }
        return inverseTable;
    }

    /**
     * Derives SCRAPE coefficients for indices 1 to n.
     * For each i ∈ [1, n], compute:
     * coeff_i = ∏_{j=1, j≠i}^{n} (α_i - α_j)^{-1} mod modulus.
     *
     * @param groupParams  the prime order/Modolus and the generator of the cyclic
     *                     subgroup (a primitive root modulo
     *                     p).
     * @param from         the starting index (should be 1).
     * @param n            the number of participants.
     * @param inverseTable the precomputed inverses for the range [ -n+1, n-1 ]
     *                     modulo modulus.
     * @param alphas       the array of evaluation points, where
     *                     alphas[1]..alphas[n] are used.
     * @return an array of SCRAPE coefficients for indices 1 to n.
     */
    public static BigInteger[] deriveScrapeCoeffs(GroupParameters groupParams, int from, int n,
            BigInteger[] inverseTable, BigInteger[] alphas) {
        BigInteger primeOrder = groupParams.getP();
        BigInteger[] coeffs = new BigInteger[n];
        for (int i = 1; i <= n; i++) {
            BigInteger coeff = BigInteger.ONE;
            for (int j = from; j <= n; j++) {
                if (i == j) {
                    continue;
                }
                // Map the difference (α_i - α_j) to an index in the inverse table.
                int index = i - j + n - 1;
                if (index < 0 || index >= inverseTable.length) {
                    throw new IllegalArgumentException("bad index " + index);
                }
                coeff = coeff.multiply(inverseTable[index]).mod(primeOrder);
                System.out.println("For i = " + i + ", j = " + j +
                        ": diff = " + (i - j) + ", index = " + index +
                        ", inverse = " + inverseTable[index]);

            }
            coeffs[i - 1] = coeff;
        }
        return coeffs;
    }

    /**
     * Derives SCRAPE coefficients for vPrimes.
     * We want vPrimes to be an array of length n+1 where:
     * vPrimes[0] = 1, and for i = 1..n, vPrimes[i] = corresponding SCRAPE
     * coefficient.
     *
     * @param groupParams  the prime order/Modolus and the generator of the cyclic
     *                     subgroup (a primitive root modulos p).
     * @param n            the number of participants.
     * @param inverseTable the precomputed inverse table.
     * @param alphas       the array of evaluation points.
     * @return an array of length n+1 containing the dual-code coefficients.
     */
    public static BigInteger[] deriveScrapeCoeffsForVPrimes(GroupParameters groupParams, int n,
            BigInteger[] inverseTable, BigInteger[] alphas) {
        // Compute SCRAPE coefficients for indices 1..n.
        BigInteger[] temp = deriveScrapeCoeffs(groupParams, 1, n, inverseTable, alphas);

        // Allocate an array of length n+1.
        BigInteger[] result = new BigInteger[n + 1];

        // Set the 0th coefficient to 1 by convention.
        result[0] = BigInteger.ONE;

        // Copy the computed SCRAPE coefficients into indices 1..n of the result array.
        System.arraycopy(temp, 0, result, 1, n);

        return result;
    }

    /**
     * Sets up the DhPvssContext with finite-field parameters according to the
     * DHPVSS public parameters:
     * pp = (G, G, p, t, n, α₀, {(αᵢ, vᵢ) : i ∈ [n]}).
     * In our finite-field implementation, all arithmetic is done modulo p.
     *
     * @param ctx         the DhPvssContext to populate.
     * @param groupParams the prime order/Modolus and the generator of the cyclic
     *                    subgroup (a primitive root modulos p).
     * @param t           the threshold.
     * @param n           the number of participants.
     */

    public static DhPvssContext dhPvssSetup(GroupParameters groupParams, int t, int n) {
        BigInteger primeOrder = groupParams.getP();
        if (primeOrder == null) {
            throw new IllegalArgumentException("No modulus specified");
        }
        if ((n - t - 2) <= 0) {
            throw new IllegalArgumentException("n and t are badly chosen");
        }

        // Allocate and fill the evaluation points (alphas) for indices 0..n.
        BigInteger[] alphas = new BigInteger[n + 1];
        for (int i = 0; i <= n; i++) {
            alphas[i] = BigInteger.valueOf(i);
        }

        // Precompute the inverse table modulo primeOrder for the range [-n+1, n-1].
        BigInteger[] inverseTable = DhPvssUtils.precomputeInverseTable(groupParams, n);

        // Compute SCRAPE coefficients for indices 1..n and store them in vs.
        BigInteger[] vs = DhPvssUtils.deriveScrapeCoeffs(groupParams, 1, n, inverseTable, alphas);

        // holder for vPrimes vector,
        // compute later if it makes sense.)
        // BigInteger[] vPrimes = DhPvssUtils.deriveScrapeCoeffsForVPrimes(groupParams,
        // n, inverseTable, alphas);

        // Choose the designated evaluation point, e.g., α₀ = alphas[0].
        BigInteger alpha0 = alphas[0];

        // Construct and return the DhPvssContext. pp = groupParams, t, n, alpha0,
        // alphas, vs
        return new DhPvssContext(groupParams, t, n, alpha0, alphas, vs);
    }

}
