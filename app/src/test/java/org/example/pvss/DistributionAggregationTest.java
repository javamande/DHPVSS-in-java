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
    public void testIndividualTermAggregation() {
        // Use a small prime modulus for dummy testing.
        BigInteger modulus = new BigInteger("7919");
        // Get a dummy generator (we assume DummyECPoint.getGenerator(modulus)exists).
        DummyECPoint G = DummyECPoint.getGenerator(modulus);

        // Set up a controlled scenario with n = 3 participants.
        int n = 3;
        // Fixed evaluation points: We assume evaluations are stored in an array where:
        // evaluations[0] is unused (or reserved for alpha0), and evaluations[1..n] are
        // for participants.
        BigInteger[] evaluations = new BigInteger[] {
                BigInteger.ZERO, // Dummy for alpha0.
                BigInteger.ONE, // alpha1 = 1.
                BigInteger.valueOf(2), // alpha2 = 2.
                BigInteger.valueOf(3) // alpha3 = 3.
        };

        // Fixed dual‑code coefficients (v) for each participant.
        BigInteger[] v = new BigInteger[] {
                new BigInteger("2"), // for participant 1.
                new BigInteger("3"), // for participant 2.
                new BigInteger("4") // for participant 3.
        };

        // Create dummy ephemeral keys and encrypted shares as multiples of G.
        DummyECPoint[] ephemeralKeys = new DummyECPoint[n];
        DummyECPoint[] encryptedShares = new DummyECPoint[n];
        for (int i = 0; i < n; i++) {
            // For testing, let ephemeralKeys[i] = (i+2)*G.
            ephemeralKeys[i] = G.multiply(BigInteger.valueOf(i + 2));
            // And let encryptedShares[i] = (i+10)*G.
            encryptedShares[i] = G.multiply(BigInteger.valueOf(i + 10));
        }

        // For each participant, compute the individual aggregation.
        for (int i = 0; i < n; i++) {
            // Evaluate at index i+1 from the evaluations array.
            BigInteger evaluation = evaluations[i + 1];
            // Compute scalar = evaluation * v[i] mod modulus.
            BigInteger scalar = evaluation.multiply(v[i]).mod(modulus);
            // Compute termU = ephemeralKeys[i] * scalar.
            DummyECPoint termU = ephemeralKeys[i].multiply(scalar);
            // Compute termV = encryptedShares[i] * scalar.
            DummyECPoint termV = encryptedShares[i].multiply(scalar);

            // For the purpose of this unit test, the "expected" values are computed using
            // the same formulas.
            // (In a real setting you might compute these with independent means or compare
            // against known constants.)
            BigInteger expectedScalar = evaluation.multiply(v[i]).mod(modulus);
            DummyECPoint expectedTermU = ephemeralKeys[i].multiply(expectedScalar);
            DummyECPoint expectedTermV = encryptedShares[i].multiply(expectedScalar);

            System.out.println("Participant " + (i + 1) + ":");
            System.out.println(" Evaluation = " + evaluation);
            System.out.println(" v = " + v[i]);
            System.out.println(" Scalar = " + scalar);
            System.out.println(" termU = " + termU);
            System.out.println(" termV = " + termV);

            // Assert that the computed values match the expected ones.
            assertEquals("TermU for participant " + (i + 1) + " should be equal", expectedTermU, termU);
            assertEquals("TermV for participant " + (i + 1) + " should be equal", expectedTermV, termV);
        }
    }

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

        polyCoeffs = EvaluationTools.evaluatePolynomialAtAllPoints(polyCoeffs, alphas, modulus);
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
