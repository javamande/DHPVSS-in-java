package org.example.pvss;

import java.math.BigInteger;

public class DHPVSS_Setup {

    /**
     * Sets up the DHPVSS context using parameters derived over the base field.
     *
     * In our finite-field implementation (which is used as the underlying
     * arithmetic for our EC group),
     * all operations are performed modulo the prime modulus p.
     *
     * @param groupParams the EC group parameters.
     * @param t           the threshold (degree of the secret sharing polynomial).
     * @param n           the number of participants.
     * @return a DhPvssContext containing the public parameters (including
     *         evaluation points and dual-code coefficients).
     */
    public static DhPvssContext dhPvssSetup(GroupGenerator.GroupParameters groupParams, int t, int n) {
        BigInteger primeOrder = groupParams.getgroupOrd();
        if (primeOrder == null) {
            throw new IllegalArgumentException("No modulus specified");
        }
        if ((n - t - 2) <= 0) {
            throw new IllegalArgumentException("n and t are badly chosen");
        }
        // Allocate and fill the evaluation points (alphas) for indices 0 to n.
        BigInteger[] alphas = new BigInteger[n + 1];
        for (int i = 0; i <= n; i++) {
            // In a real implementation, these should be distinct, nonzero values.
            alphas[i] = BigInteger.valueOf(i);
        }

        // Precompute an inverse table for the range [–(n–1), …, n–1] modulo p.
        BigInteger[] inverseTable = DhPvssUtils.precomputeInverseTable(groupParams, n);

        // Compute the SCRAPE coefficients for indices 1..n.
        BigInteger[] vs = DhPvssUtils.deriveScrapeCoeffs(groupParams, 1, n, inverseTable, alphas);

        // You could also compute the extended dual-code vector vPrimes if needed:
        // BigInteger[] vPrimes = deriveScrapeCoeffsForVPrimes(groupParams, n,
        // inverseTable, alphas);

        // // The designated evaluation point alpha0 is often chosen as alphas[0]
        // // (typically 0).
        // BigInteger alpha0 = alphas[0];

        // Construct and return the DHPVSS context.
        return new DhPvssContext(groupParams, t, n, alphas, vs);
    }

}
