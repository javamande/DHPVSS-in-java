package org.example.pvss;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Implements Shamir secret sharing over an elliptic curve for DHPVSS.
 * The dealer’s random polynomial is defined over the underlying field as:
 *
 * m(x) = c₁ * x + c₂ * x² + … + cₜ * xᵗ (mod q),
 *
 * ensuring m(0) = 0.
 * Then, if the dealer’s secret is S ∈ G (computed as S = s·G),
 * the share for participant i (with evaluation point αᵢ, i ≥ 1) is defined as:
 *
 * Aᵢ = S + [ m(αᵢ) · G ]
 *
 * where the scalar m(αᵢ) ∈ Z_q is computed by evaluating the polynomial m at
 * αᵢ.
 */
public class SSS_EC {

    /**
     * Generates shares for an elliptic curve–based Shamir secret sharing scheme.
     *
     * @param ctx the PVSS context containing public parameters (including
     *            evaluation points)
     * @param s   the dealer’s secret scalar (so that the dealer’s secret S = s·G)
     * @return an array of ECPoints, one share per participant.
     */
    public static ECPoint[] generateSharesEC(DhPvssContext ctx, ECPoint S) {
        // Number of participants and threshold.
        int n = ctx.getNumParticipants();
        int t = ctx.getThreshold();
        // p is the field modulus; we use it for arithmetic in Z_q.
        BigInteger q = ctx.getGroupParameters().getN();
        // Retrieve the evaluation points, α₀, α₁, …, αₙ.
        BigInteger[] alphas = ctx.getAlphas();

        // Define the random polynomial m(x) = c₁*x + c₂*x² + ... + cₜ*xᵗ mod p, i.e.,
        // with m(0)=0.
        // We need t random coefficients.
        BigInteger[] coeffs = new BigInteger[t + 1];
        coeffs[0] = BigInteger.ZERO; // Ensure m(0)=0.
        SecureRandom random = new SecureRandom();
        for (int j = 1; j <= t; j++) {
            coeffs[j] = new BigInteger(q.bitLength(), random).mod(q);
        }

        // Allocate space for the shares (for participants 1 through n).
        ECPoint[] shares = new ECPoint[n];
        // For each participant i, evaluate m(αᵢ) and compute
        // Aᵢ = S + (G · m(αᵢ)).
        for (int i = 1; i <= n; i++) {
            BigInteger x = alphas[i]; // Evaluation point for participant i.
            BigInteger mEval = BigInteger.ZERO;
            // Evaluate m(x) = Σ_{j=1}^{t} (c_j * x^j) mod q.
            for (int j = 1; j <= t; j++) {
                BigInteger term = coeffs[j].multiply(x.modPow(BigInteger.valueOf(j), q)).mod(q);
                mEval = mEval.add(term).mod(q);
            }
            // Compute the masked part as G · m(αᵢ).
            ECPoint mask = ctx.getGenerator().multiply(mEval).normalize();
            // The share Aᵢ = S + mask.
            shares[i - 1] = S.add(mask).normalize();
        }
        return shares;
    }

    /**
     * Reconstructs the dealer’s secret S from a subset of shares using Lagrange
     * interpolation at x = 0.
     *
     * Given shares Aᵢ = S + (m(αᵢ) · G) for i in I, reconstruction computes:
     *
     * S' = Σ_{i in I} λ_i · A_i,
     *
     * where λ_i are the Lagrange coefficients computed in the underlying field at x
     * = 0,
     * which ensures that Σ λ_i·m(α_i) = m(0) = 0.
     *
     * @param ctx     the PVSS context.
     * @param shares  the selected shares (ECPoints) for participants in I.
     * @param indices the corresponding evaluation point indices (values in {1, …,
     *                n}).
     * @return the reconstructed secret S as an ECPoint.
     */
    public static ECPoint reconstructSecretEC(DhPvssContext ctx, ECPoint[] shares, int[] indices) {
        if (shares.length != indices.length) {
            throw new IllegalArgumentException("Number of shares must equal number of indices.");
        }
        int k = shares.length;
        BigInteger subgroupprime = ctx.getGroupParameters().getN();
        BigInteger[] alphas = ctx.getAlphas();

        // The reconstruction is performed at x = 0.
        BigInteger x0 = BigInteger.ZERO;

        // Initialize S_reconstructed to the identity element (point at infinity) in G.
        ECPoint S_reconstructed = ctx.getGenerator().getCurve().getInfinity();

        // Compute Lagrange coefficients λ_i for each share.
        for (int i = 0; i < k; i++) {
            int idx = indices[i]; // Evaluation point for the i-th share.
            BigInteger lambda = BigInteger.ONE;
            for (int j = 0; j < k; j++) {
                if (i == j) {
                    continue;
                }
                int idxJ = indices[j];
                // Lagrange coefficient for share i:
                // λ_i = ∏_{j≠i} ((0 - α_j)/(α_i - α_j)) mod p.
                BigInteger numerator = x0.subtract(alphas[idxJ]).mod(subgroupprime);
                BigInteger denominator = alphas[idx].subtract(alphas[idxJ]).mod(subgroupprime);
                BigInteger invDenom = denominator.modInverse(subgroupprime);
                lambda = lambda.multiply(numerator.multiply(invDenom)).mod(subgroupprime);
            }
            System.out.println("Lagrange coefficient for share at index " + idx + " = " + lambda);
            // Accumulate the share multiplied by its Lagrange coefficient.
            S_reconstructed = S_reconstructed.add(shares[i].multiply(lambda));
        }
        return S_reconstructed.normalize();
    }
}
