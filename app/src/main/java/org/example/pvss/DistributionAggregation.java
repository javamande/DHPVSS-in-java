package org.example.pvss;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

public class DistributionAggregation {

    /**
     * Given the following inputs:
     * - polyCoeffs: an array of BigIntegers representing the coefficients of the
     * polynomial m*(X) (obtained from hashing inputs).
     * - alphas: the evaluation points (α₁, …, αₙ) for participants (note: index 0
     * is reserved for α₀).
     * - v: the dual‑code coefficients (v₁, …, vₙ).
     * - ephemeralKeys: the array of ephemeral public keys Eᵢ.
     * - encryptedShares: the array of encrypted shares Cᵢ.
     * - modulus: the prime modulus (or group order if needed for reduction)
     *
     * This method computes:
     * U = ∑ [vᵢ · m*(αᵢ)] · Eᵢ (using EC point addition)
     * V = ∑ [vᵢ · m*(αᵢ)] · Cᵢ (using EC point addition)
     * which (in a multiplicative notation) would be equivalent to
     * U = ∏ Eᵢ^(vᵢ · m*(αᵢ)) and V = ∏ Cᵢ^(vᵢ · m*(αᵢ)).
     *
     * @param polyCoeffs      the polynomial coefficients (from hash-to-poly)
     * @param alphas          the evaluation points (ECPoints not used directly here
     *                        but the α’s as scalars)
     * @param v               the dual-code coefficients
     * @param ephemeralKeys   the ephemeral public keys Eᵢ (ECPoints)
     * @param encryptedShares the encrypted shares Cᵢ (ECPoints)
     * @param modulus         the modulus for scalar arithmetic (typically the group
     *                        order, or the prime p)
     * @return a two-element array containing U (at index 0) and V (at index 1)
     */
    public static ECPoint[] aggregateUV(BigInteger[] polyCoeffs, BigInteger[] alphas, BigInteger[] v,
            ECPoint[] ephemeralKeys, ECPoint[] encryptedShares, BigInteger modulus) {
        // We assume polyCoeffs has length k (for k = n - t - 1, say)
        // And we need to evaluate the polynomial m*(X) at each evaluation point αᵢ.
        // Create an array to hold the evaluation results.
        int n = ephemeralKeys.length;
        BigInteger[] evaluations = new BigInteger[n + 1];
        // We assume that evaluations are computed for indices 1..n (skipping α₀).
        // (Alternatively, if your ctx already stores evaluated m*(αᵢ), you could
        // retrieve them directly.)
        for (int i = 1; i <= n; i++) {
            // Evaluate m*(αᵢ) = polyCoeffs[0] + polyCoeffs[1]*(αᵢ)^1 + polyCoeffs[2]*(αᵢ)^2
            // + … mod modulus.
            evaluations[i] = EvaluationTools.evaluatePolynomial(polyCoeffs, alphas[i], modulus);
        }

        // Initialize U and V as the identity element of the EC group.
        // For an elliptic curve in additive notation, that is the point at infinity.
        ECPoint U = ephemeralKeys[0].getCurve().getInfinity();
        ECPoint V = encryptedShares[0].getCurve().getInfinity();

        // For each participant i, compute:
        // scalar_i = evaluations[i] * v[i] mod modulus.
        // Then compute termU = Eᵢ * scalar_i and termV = Cᵢ * scalar_i.
        // Aggregate U = U + termU, and V = V + termV.
        for (int i = 1; i <= n; i++) {
            BigInteger scalar = evaluations[i].multiply(v[i - 1]).mod(modulus);
            ECPoint termU = ephemeralKeys[i - 1].multiply(scalar).normalize();
            ECPoint termV = encryptedShares[i - 1].multiply(scalar).normalize();

            U = U.add(termU).normalize();
            V = V.add(termV).normalize();

            // For debugging, print intermediate terms.
            System.out.println("Participant " + i + ":");
            System.out.println("  evaluation m*(α_" + i + ") = " + evaluations[i]);
            System.out.println("  Dual-code v[" + i + "] = " + v[i - 1]);
            System.out.println("  Scalar = " + scalar);
            System.out.println("  termU = " + termU);
            System.out.println("  termV = " + termV);
        }

        System.out.println("Aggregated U: " + U);
        System.out.println("Aggregated V: " + V);

        return new ECPoint[] { U, V };
    }
}
