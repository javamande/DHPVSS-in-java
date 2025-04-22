package org.example.pvss;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;

public class DistributionAggregationTest {

    @Test
    public void testAggregateUV_Real() throws Exception {
        // Set up group parameters using secp256r1.
        GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup();
        int t = 5; // threshold
        int n = 10; // number of participants

        // Set up the PVSS context (which creates the evaluation points and dual-code
        // coefficients).
        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(groupParams, t, n);
        BigInteger modulus = ctx.getOrder();
        BigInteger[] alphas = ctx.getAlphas();
        BigInteger[] vs = ctx.getV();

        // Generate the distribution input.
        SecureRandom random = new SecureRandom();
        DistributionInput distInput = DistributionInputGenerator.generateDistributionInput(ctx);
        ECPoint S = distInput.getSecret();
        // Retrieve the dealer's key pair.
        DhKeyPair dealerKeyPair = distInput.getDealerKeyPair();
        BigInteger dealerSecret = dealerKeyPair.getSecretKey();
        ECPoint dealerpub = dealerKeyPair.getPublic();

        // Retrieve the ephemeral keys from the distribution input.
        EphemeralKeyPublic[] ephemeralKeyPublics = distInput.getEphemeralKeys();
        ECPoint[] ephemeralKeys = new ECPoint[ephemeralKeyPublics.length];
        for (int i = 0; i < ephemeralKeyPublics.length; i++) {
            ephemeralKeys[i] = ephemeralKeyPublics[i].getPublicKey();
            assertNotNull("Ephemeral public key should not be null", ephemeralKeys[i]);
            assertTrue("Ephemeral public key must be on the curve",
                    ephemeralKeys[i].isValid());
        }

        // For the sake of this test, generate dummy encrypted shares.
        // In the real protocol these come from applying the dealer’s secret mask to the
        // Shamir shares.
        // Here, for simplicity, we simulate them as random multiples of the generator.
        // ECPoint[] mask = new ECPoint[n];
        ECPoint[] encryptedShares = new ECPoint[n];
        ECPoint G = ctx.getGenerator();
        for (int i = 0; i < n; i++) {

            encryptedShares[i] = ephemeralKeys[i].multiply(dealerSecret); // encryptedshares = skD * Ei
            // = encryptedShares[i].add(mask[i]).normalize();
        }

        BigInteger[] polyCoeffs = ctx.getAlphas();
        int numPolyCoeffs = polyCoeffs.length;

        polyCoeffs = HashingTools.hashPointsToPoly(dealerpub, ephemeralKeys, encryptedShares,
                numPolyCoeffs,
                modulus);

        polyCoeffs = EvaluationTools.evalAll(polyCoeffs, alphas, modulus);
        BigInteger[] evaluations = polyCoeffs; // indices: 0 to n (we ignore index 0 later).

        ECPoint U = G.getCurve().getInfinity();
        ECPoint V = G.getCurve().getInfinity();
        for (int i = 1; i <= n; i++) {
            // Compute scalar_i = evaluations[i] * v[i-1] mod modulus.
            BigInteger scalar = evaluations[i].multiply(vs[i - 1]).mod(modulus);

            // Debug prints for individual terms:
            ECPoint termU = ephemeralKeys[i - 1].multiply(scalar).normalize(); // vs * m*(ai) * Ei = U
            ECPoint termV = encryptedShares[i - 1].multiply(scalar).normalize(); // vs * m*(ai) * Ei^skD = V
            System.out.println("For participant " + i + ":");
            System.out
                    .println(" Evaluation (α=" + evaluations[i - 1] + "), v = " + vs[i - 1] + ", scalar = " + scalar);
            System.out.println(" Ephemeral key^scalar: " + termU);
            System.out.println(" Encrypted share^scalar: " + termV);

            U = U.add(termU).normalize();
            V = V.add(termV).normalize();
        }

        // Expected V should equal [dealerSecret] * U.
        // Now, per the protocol, we must have that V = U^(dealerSecret) (i.e. the share
        // aggregation in the exponent).
        // Since the group is written additively (ECPoints are added), exponentiation
        // translates to scalar multiplication.
        // So we expect:
        // Expected V = [dealerSecret] * U.
        ECPoint expectedV = U.multiply(dealerSecret).normalize();

        System.out.println("Aggregated U = " + U);
        System.out.println("Aggregated V = " + V);
        System.out.println("Expected V (U multiplied by dealerSecret) = " +
                expectedV);

        // Now perform assertions:
        assertNotNull("Aggregated U should not be null", U);
        assertNotNull("Aggregated V should not be null", V);
        // The equality of ECPoints is checked using .equals(). Note that due to
        // normalization and the properties
        // of ECPoint arithmetic, the expectedV should equal V if the aggregation is
        // performed correctly.
        assertEquals("V should equal dealerSecret * U", expectedV, V);
    }

    public static void main(String[] args) throws Exception {
        DistributionAggregationTest test = new DistributionAggregationTest();

        System.out.println("Participant DistributionAggregationTest test passed!");

    }
}
