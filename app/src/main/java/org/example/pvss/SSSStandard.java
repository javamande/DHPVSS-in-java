package org.example.pvss;

import java.math.BigInteger;
import java.security.SecureRandom;

public class SSSStandard {

    /**
     * Generates shares for standard Shamir secret sharing.
     * The dealer’s polynomial is defined as:
     * 
     * m(X) = S + a₁*X + a₂*X² + ... + aₜ*Xᵗ (mod p)
     * 
     * where:
     * - S is the dealer's secret (a group element, e.g. S = G * s)
     * - The coefficients a₁, …, aₜ are chosen uniformly at random from Zₚ,
     * - m(0) = S.
     * 
     * The share for participant i (with evaluation point αᵢ) is:
     * 
     * Aᵢ = m(αᵢ) mod p.
     * 
     * @param ctx    the PVSS context holding public parameters (p, generator G,
     *               evaluation points, etc.)
     * @param secret the dealer’s secret as a group element (for example, S = G * s
     *               mod p)
     * @return an array of shares (Aᵢ for i = 1, …, n)
     */
    public static BigInteger[] generateSharesStandard(DhPvssContext ctx, BigInteger secret) {
        int n = ctx.getNumParticipants(); // Total number of participants (shares to generate)
        int t = ctx.getThreshold(); // Threshold; degree t polynomial (thus t+1 coefficients)
        BigInteger p = ctx.getOrder(); // The prime modulus p of Zₚ
        BigInteger[] alphas = ctx.getAlphas(); // Evaluation points: [α₀, α₁, …, αₙ]

        // --- Step 1: Define the dealer’s polynomial m(X) ---
        // We set m(X) = S + a₁*X + a₂*X² + ... + aₜ*Xᵗ mod p.
        // This guarantees that m(0) = S.
        BigInteger[] coeffs = new BigInteger[t + 1];
        coeffs[0] = secret; // Constant term is the secret S.
        SecureRandom random = new SecureRandom();
        for (int j = 1; j <= t; j++) {
            // Random coefficients a_j are sampled uniformly from Zₚ.
            coeffs[j] = new BigInteger(p.bitLength(), random).mod(p);
        }

        // --- Step 2: Compute the shares by evaluating m(X) at each evaluation point αᵢ
        // ---
        // For each participant i (i = 1, …, n), compute:
        // Aᵢ = m(αᵢ) = S + a₁*(αᵢ) + a₂*(αᵢ)² + ... + aₜ*(αᵢ)ᵗ mod p.
        BigInteger[] shares = new BigInteger[n];
        for (int i = 1; i <= n; i++) { // i corresponds to participant i
            BigInteger x = alphas[i]; // Evaluation point for participant i.
            BigInteger mEval = BigInteger.ZERO; // This will accumulate m(αᵢ)
            for (int j = 0; j <= t; j++) {
                // For j = 0, we have: term = S * (αᵢ)^0 = S.
                // For j >= 1, term = a_j * (αᵢ)^j.
                BigInteger term = coeffs[j].multiply(x.modPow(BigInteger.valueOf(j), p)).mod(p);
                mEval = mEval.add(term).mod(p);
            }
            // Set the share for participant i to be the evaluation of m(X) at αᵢ.
            shares[i - 1] = mEval; // Aᵢ = m(αᵢ) mod p.
        }
        return shares;
    }

    /**
     * Reconstructs the secret S from a set of shares using Lagrange interpolation
     * at x = 0.
     * 
     * Given shares Aᵢ = m(αᵢ) for i in I ⊆ {1, …, n}, with m(0) = S,
     * the secret S is reconstructed as:
     * 
     * S = Σ_{i in I} λ_i * A_i mod p,
     * 
     * where the Lagrange coefficient for share i is:
     * 
     * λ_i = ∏_{j in I, j ≠ i} ((0 - α_j) / (α_i - α_j)) mod p.
     * 
     * @param ctx     the PVSS context (provides the prime modulus p and evaluation
     *                points)
     * @param shares  the shares A_i for the selected participants (as BigIntegers)
     * @param indices the indices corresponding to the shares (values in {1, …, n}).
     *                For example, if using shares for participants 1, 2, and 3,
     *                indices = {1, 2, 3}.
     * @return the reconstructed secret S (a group element in Zₚ)
     */
    public static BigInteger reconstructSecretStandard(DhPvssContext ctx, BigInteger[] shares, int[] indices) {
        if (shares.length != indices.length) {
            throw new IllegalArgumentException("Number of shares must equal number of indices.");
        }
        BigInteger p = ctx.getOrder();
        BigInteger[] alphas = ctx.getAlphas();
        // We interpolate at x = 0, since m(0) = S.
        BigInteger x0 = BigInteger.ZERO;
        BigInteger S_reconstructed = BigInteger.ZERO;

        // For each share, compute its Lagrange coefficient.
        // For share corresponding to evaluation point α_i, the coefficient is:
        // λ_i = ∏_{j ≠ i} ((0 - α_j) / (α_i - α_j)) mod p.
        for (int i = 0; i < shares.length; i++) {
            int idx = indices[i]; // This gives the evaluation point α_idx for the i-th share.
            BigInteger lambda = BigInteger.ONE;
            for (int j = 0; j < shares.length; j++) {
                if (i == j) {
                    continue;
                }
                int idx_j = indices[j];
                // Numerator: (0 - α_j) mod p.
                BigInteger numerator = x0.subtract(alphas[idx_j]).mod(p);
                // Denominator: (α_i - α_j) mod p.
                BigInteger denominator = alphas[idx].subtract(alphas[idx_j]).mod(p);
                BigInteger invDenom = denominator.modInverse(p);
                lambda = lambda.multiply(numerator.multiply(invDenom)).mod(p);
            }
            System.out.println("Lagrange coefficient for share at index " + idx + " = " + lambda);
            // Accumulate the contribution: S_reconstructed += λ_i * A_i.
            S_reconstructed = S_reconstructed.add(shares[i].multiply(lambda)).mod(p);
        }
        return S_reconstructed;
    }

}
