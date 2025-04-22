package org.example.pvss;

import java.math.BigInteger;
import java.util.Arrays;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Publicly Verifiable Secret Sharing (PVSS) verify routine for DHPVSS.
 */
public class DHPVSS_Verify {

    /**
     * Verifies the dealer's distribution proof:
     * - recomputes the weighted aggregates U, V from the ephemeral public keys and
     * encrypted shares
     * - checks the DLEQ proof that V = sk_D * U under public key pkD
     *
     * @param ctx       the PVSS context (group, alphas, dual-coeffs)
     * @param pkD       the dealer's public key (sk_D * G)
     * @param ephemeral array of participants' ephemeral public keys E_i
     * @param encrypted array of encrypted shares C_i = A_i + sk_D*E_i
     * @param dleqProof the proof asserting V = sk_D * U
     * @return true if the proof and aggregation check out, false otherwise
     */
    public static boolean verify(
            DhPvssContext ctx,
            ECPoint pkD,
            ECPoint[] ephemeral,
            ECPoint[] encrypted,
            NizkDlEqProof dleqProof) {
        int n = ctx.getNumParticipants();
        if (ephemeral.length != n || encrypted.length != n) {
            throw new IllegalArgumentException(
                    "Expected arrays of length " + n + ", got " + ephemeral.length + "/" + encrypted.length);
        }

        BigInteger p = ctx.getOrder();
        ECPoint G = ctx.getGenerator();

        // 1) Derive hash-chain polynomial coefficients
        // degree = n - t - 2, numCoeffs = degree+1
        int degree = n - ctx.getThreshold() - 2;
        int numCoeffs = degree + 1;
        BigInteger[] coeffs = HashingTools.hashPointsToPoly(
                pkD,
                ephemeral,
                encrypted,
                numCoeffs,
                p);

        // System.out.println("coeffs = : " + Arrays.toString(coeffs));

        // 2) Evaluate at each alpha_i
        BigInteger[] alphas = ctx.getAlphas();
        BigInteger[] evals = new BigInteger[n + 1];
        for (int i = 1; i <= n; i++) {
            evals[i] = EvaluationTools.evaluatePolynomial(coeffs, alphas[i], p);
        }

        // 3) Compute weighted aggregate U and V
        BigInteger[] v = ctx.getV();
        ECPoint U = G.getCurve().getInfinity();
        ECPoint V = G.getCurve().getInfinity();

        for (int i = 1; i <= n; i++) {
            BigInteger r = evals[i].multiply(v[i - 1]).mod(p);
            U = U.add(ephemeral[i - 1].multiply(r)).normalize();
            V = V.add(encrypted[i - 1].multiply(r)).normalize();
        }
        System.out.println("verify() recomputed U = " + U);
        System.out.println("verify() recomputed V = " + V);
        System.out.println("  proof.challenge = " + dleqProof.getChallenge());
        System.out.println("  proof.response  = " + dleqProof.getResponse());

        // 4) Verify DLEQ proof: V = sk_D * U under pkD
        return NizkDlEqProof.verifyProof(ctx, U, pkD, V, dleqProof);
    }
}