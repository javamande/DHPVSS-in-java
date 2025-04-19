package org.example.pvss;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Shamir secret sharing over an elliptic curve in the DHPVSS (YOSO) model.
 * Dealer holds a long‑term scalar sk_D ∈ ℤₚ and publishes its group share
 * S = G · sk_D ∈ 𝔾. A random polynomial m(x) of degree t with m(0)=0 is
 * used to mask S across n roles (committee positions).
 *
 * Polynomial m(x) = c₁·x + c₂·x² + … + cₜ·xᵗ mod p, with random coefficients
 * c₁,…,cₜ ∈ ℤₚ.
 * For role i with evaluation point αᵢ, dealer computes share:
 * A_i = S + G·m(αᵢ) ∈ 𝔾.
 */
public class GShamir_Share {

    /**
     * Generate DHPVSS shares A_i = S + G·m(αᵢ) for all i=1..n.
     * 
     * @param ctx DHPVSS context holding G ∈ 𝔾, p=|𝔾|, alphas α₀…αₙ, threshold t,
     *            and n.
     * @param S   Dealer’s group share S = G·sk_D.
     * @return Array of n ECPoints, one share A_i per role i.
     */
    public static ECPoint[] generateSharesEC(DhPvssContext ctx, ECPoint S) {
        int n = ctx.getNumParticipants(); // total roles
        int t = ctx.getThreshold(); // degree
        BigInteger p = ctx.getOrder(); // prime order p of 𝔾
        ECPoint G = ctx.getGenerator(); // generator of 𝔾
        BigInteger[] alphas = ctx.getAlphas(); // α₀…αₙ

        // Build random polynomial m(x) with m(0)=0
        BigInteger[] coeffs = new BigInteger[t + 1];
        coeffs[0] = BigInteger.ZERO;
        SecureRandom rnd = new SecureRandom();
        for (int j = 1; j <= t; j++) {
            coeffs[j] = new BigInteger(p.bitLength(), rnd).mod(p);
        }

        ECPoint[] shares = new ECPoint[n];
        for (int i = 1; i <= n; i++) {
            BigInteger x = alphas[i];
            BigInteger mEval = BigInteger.ZERO;
            // evaluate m(αᵢ)
            for (int j = 1; j <= t; j++) {
                BigInteger term = coeffs[j].multiply(x.modPow(BigInteger.valueOf(j), p)).mod(p);
                mEval = mEval.add(term).mod(p);
            }
            // A_i = S + G·m(αᵢ)
            ECPoint Ai = S.add(G.multiply(mEval));
            shares[i - 1] = Ai.normalize();
        }
        return shares;
    }

    /**
     * Reconstruct dealer’s group share S from at least t+1 role shares A_i.
     * Using Lagrange interpolation at x=0:
     * S = Σ_{i∈I} λ_i · A_i
     * with λ_i computed over ℤₚ so that Σ λ_i·m(αᵢ) = m(0) = 0.
     * 
     * @param ctx     DHPVSS context
     * @param shares  ECPoints A_i for roles in subset I
     * @param indices 1-based indices i ∈ I corresponding to αᵢ
     * @return Recovered group share S ∈ 𝔾
     */
    public static ECPoint reconstructSecretEC(DhPvssContext ctx, ECPoint[] shares, int[] indices) {
        if (shares.length != indices.length) {
            throw new IllegalArgumentException("Share count must match indices count");
        }
        int k = shares.length;
        BigInteger p = ctx.getOrder();
        BigInteger[] alphas = ctx.getAlphas();
        ECPoint Srec = ctx.getGenerator().getCurve().getInfinity();
        BigInteger x0 = BigInteger.ZERO; // interpolation at 0

        for (int i = 0; i < k; i++) {
            int idx = indices[i];
            BigInteger λ = BigInteger.ONE;
            for (int j = 0; j < k; j++) {
                if (i == j)
                    continue;
                int idxJ = indices[j];
                BigInteger num = x0.subtract(alphas[idxJ]).mod(p);
                BigInteger den = alphas[idx].subtract(alphas[idxJ]).mod(p);
                λ = λ.multiply(num.multiply(den.modInverse(p))).mod(p);
            }
            Srec = Srec.add(shares[i].multiply(λ));
        }
        return Srec.normalize();
    }
}
