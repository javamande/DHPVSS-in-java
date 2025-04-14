package org.example.pvss;

import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;
import org.example.pvss.DHPVSS_Dist.DistributionResult;
import org.junit.Test;

public class DistributionTest {

    /**
     * Evaluates a polynomial (given as an array of BigIntegers representing the
     * coefficients)
     * at a given evaluation point x modulo modulus.
     * The polynomial is: m*(X) = m*[0] + m*[1]*X + m*[2]*X^2 + ... mod modulus.
     *
     * @param polyCoeffs the coefficients of the polynomial
     * @param x          the evaluation point (as a BigInteger)
     * @param modulus    the modulus (prime order)
     * @return the evaluated value m*(x) mod modulus
     */
    public static BigInteger evaluatePolynomial(BigInteger[] polyCoeffs, BigInteger x, BigInteger modulus) {
        BigInteger result = BigInteger.ZERO;
        for (int j = 0; j < polyCoeffs.length; j++) {
            BigInteger term = polyCoeffs[j].multiply(x.modPow(BigInteger.valueOf(j), modulus)).mod(modulus);
            result = result.add(term).mod(modulus);
        }
        return result;
    }

    /**
     * Aggregates the ephemeral keys and encrypted shares.
     * For each participant i (with evaluation point αᵢ), we first compute aᵢ =
     * m*(αᵢ)
     * using the hashed polynomial coefficients. Then, we compute:
     * 
     * U = Σ (aᵢ · Eᵢ) and V = Σ (aᵢ · Cᵢ).
     * 
     * @param polyCoeffs      the polynomial coefficients m* (as computed from the
     *                        hash)
     * @param alphas          the evaluation points (indexed from 1 to n in this
     *                        context)
     * @param ephemeralKeys   the array of ephemeral keys Eᵢ (ECPoints)
     * @param encryptedShares the array of encrypted shares Cᵢ (ECPoints)
     * @param modulus         the prime modulus (p)
     * @return an array containing U at index 0 and V at index 1.
     */
    public static ECPoint[] aggregateEU(BigInteger[] polyCoeffs, BigInteger[] alphas,
            ECPoint[] ephemeralKeys, ECPoint[] encryptedShares, BigInteger modulus, DhPvssContext ctx) {
        // For EC groups, "aggregation" means adding up the contributions (each computed
        // by scalar multiplication)
        ECPoint U = ctx.getGenerator().getCurve().getInfinity();
        ECPoint V = ctx.getGenerator().getCurve().getInfinity();

        // Here, we assume that alphas[1] ... alphas[n] correspond to participant
        // evaluation points.
        for (int i = 1; i < alphas.length; i++) { // i from 1 to n
            // Evaluate the polynomial at αᵢ:
            BigInteger a_i = evaluatePolynomial(polyCoeffs, alphas[i], modulus);
            // Compute contribution: a_i * ephemeralKeys[i-1] and a_i * encryptedShares[i-1]
            ECPoint termU = ephemeralKeys[i - 1].multiply(a_i);
            ECPoint termV = encryptedShares[i - 1].multiply(a_i);
            U = U.add(termU);
            V = V.add(termV);
        }
        return new ECPoint[] { U.normalize(), V.normalize() };
    }

    /**
     * Tests the distribution verification by aggregating U and V from the ephemeral
     * keys and encrypted shares,
     * computing the hashed polynomial from the dealer's public key and the set of
     * (ephemeralKey, encryptedShare) pairs,
     * and then verifying the DLEQ proof that shows V = sk_D * U.
     */
    @Test
    public void testDistributionVerification() throws Exception {
        // Set parameters.
        int t = 2; // threshold
        int n = 5; // number of participants

        // Generate the PVSS context (using your elliptic-curve group based setup).
        GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup();
        DhPvssContext ctx = DhPvssUtils.dhPvssSetup(groupParams, t, n);
        BigInteger p = ctx.getOrder();

        // For testing, generate an array of ephemeral keys for the participants.
        SecureRandom random = new SecureRandom();
        ECPoint[] ephemeralKeys = new ECPoint[n];
        for (int i = 0; i < n; i++) {
            // Each ephemeral key is generated as: Eᵢ = G * rᵢ, where rᵢ is random.
            BigInteger r = new BigInteger(ctx.getGroupParameters().getN().bitLength(), random)
                    .mod(ctx.getGroupParameters().getN());
            ephemeralKeys[i] = ctx.getGenerator().multiply(r).normalize();
        }

        // Generate the dealer's key pair.
        DhKeyPair dealerKeyPair = DhKeyPair.generate(ctx, random);
        ECPoint dealerPub = dealerKeyPair.getPublic();

        // Choose the dealer's secret s (as a scalar) and compute the secret group
        // element: S = G * s.
        BigInteger s = BigInteger.valueOf(13);
        ECPoint S = ctx.getGenerator().multiply(s).normalize();

        // --- Suppose we have run the distribution phase already ---
        // (For the purposes of this test, assume that you have already obtained the
        // encrypted shares
        // as an array of ECPoints. Here, for example, we call your distribution
        // function.)
        DistributionResult distRes = DHPVSS_Dist.distribute(ctx, ephemeralKeys, dealerKeyPair, s);
        ECPoint[] encryptedShares = distRes.getEncryptedShares();
        NizkDlEqProof dleqProof = distRes.getDleqProof();

        // --- Now, we need to compute the "hash polynomial" m*.
        // In the protocol, m* = H(pk_D, { (Eᵢ, Cᵢ) : i in [n] }).
        // Assume that your HashingTools.hashPointsToPoly is refactored to take
        // ECPoints.
        int numPolyCoeffs = n - t - 1; // as given in the protocol.
        // (We now hash over the dealer's public key, the ephemeral keys, and the
        // encrypted shares.)
        BigInteger[] polyCoeffs = HashingTools.hashPointsToPoly(dealerPub, ephemeralKeys, encryptedShares,
                numPolyCoeffs, p);
        System.out.println("Polynomial coefficients from hash:");
        for (int i = 0; i < polyCoeffs.length; i++) {
            System.out.println("  Coefficient[" + i + "] = " + polyCoeffs[i]);
        }

        // --- Aggregate the values U and V.
        // For each participant i, evaluate m*(αᵢ) using the evaluation point αᵢ from
        // the context.
        BigInteger[] alphas = ctx.getAlphas(); // assume alphas[1..n] correspond to participants.
        ECPoint[] UV = aggregateEU(polyCoeffs, alphas, ephemeralKeys, encryptedShares, p, ctx);
        ECPoint U = UV[0];
        ECPoint V = UV[1];
        System.out.println("Computed aggregated U: " + U);
        System.out.println("Computed aggregated V: " + V);

        // --- Finally, verify the DLEQ proof.
        // The DLEQ proof should prove that V = sk_D * U,
        // i.e. that the same scalar (the dealer’s secret) was used.
        boolean validProof = NizkDleqProofVerificator.verifyProof(ctx, U, dealerPub, V, dleqProof);
        System.out.println("DLEQ proof verification result: " + validProof);

        // Assert that the DLEQ proof verifies correctly.
        assertTrue("The DLEQ proof must verify", validProof);
    }
}
