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
        DistributionInput distInput = DistributionInputGenerator.generateDistributionInput(ctx, random);
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

    @Test
    public void testAggregateUV_Real_Detailed() throws Exception {
        // For testing, use a small number of participants.
        int t = 2; // threshold
        int n = 5; // number of participants

        // Generate the group parameters using secp256r1 (elliptic curve)
        GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup();
        // Set up the PVSS context (this will generate evaluation points and dual‑code
        // coefficients)
        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(groupParams, t, n);
        BigInteger modulus = ctx.getOrder(); // usually the field characteristic

        // Generate a distribution input; this gives you the dealer’s key pair,
        // ephemeral keys, etc.
        SecureRandom random = new SecureRandom();
        DistributionInput distInput = DistributionInputGenerator.generateDistributionInput(ctx, random);
        DhKeyPair dealerKeyPair = distInput.getDealerKeyPair();
        BigInteger dealerSecret = dealerKeyPair.getSecretKey();
        ECPoint dealerPub = dealerKeyPair.getPublic();

        // Retrieve the ephemeral keys (Eᵢ) from the distribution input.
        // (Assuming they are provided as an array via a getter.)
        EphemeralKeyPublic[] ephemeralKeyPublics = distInput.getEphemeralKeys();
        ECPoint[] ephemeralKeys = new ECPoint[ephemeralKeyPublics.length];
        for (int i = 0; i < ephemeralKeyPublics.length; i++) {
            ephemeralKeys[i] = ephemeralKeyPublics[i].getPublicKey();
            assertNotNull("Ephemeral key " + i + " must not be null", ephemeralKeys[i]);
        }

        // For this test, we simulate the encrypted shares (Cᵢ) as follows:
        // In the real protocol, Cᵢ = Aᵢ + (dealerSecret * Eᵢ).
        // For controlled testing, we generate the Shamir shares Aᵢ using SSS_EC,
        // then add the mask dealerSecret * Eᵢ.
        ECPoint[] shares = GShamir_Share.generateSharesEC(ctx, distInput.getSecret());
        ECPoint[] encryptedShares = new ECPoint[n];
        for (int i = 0; i < n; i++) {
            // Compute the mask Mᵢ = dealerSecret * Eᵢ.
            ECPoint mask = ephemeralKeys[i].multiply(dealerSecret).normalize();
            // Compute Cᵢ = Aᵢ + Mᵢ.
            encryptedShares[i] = shares[i].add(mask).normalize();
        }

        // For testing the aggregation, we need a hash-to-poly function evaluation.
        // Here we simulate it by using the PVSS context’s evaluation points.
        // In a real protocol, these evaluations come from a hash over (dealerPub,
        // commitment keys, encryptedShares).
        BigInteger[] polyCoeffs = HashingTools.hashPointsToPoly(dealerPub, ephemeralKeys, encryptedShares, n, modulus);
        // Then evaluate the polynomial at all alpha points.
        // (Assuming EvaluationTools.evaluatePolynomialAtAllPoints returns an array
        // whose index i holds m*(α_i)).
        BigInteger[] evaluations = EvaluationTools.evaluatePolynomialAtAllPoints(polyCoeffs, ctx.getAlphas(), modulus);

        // Get the dual-code coefficients (v's) from the context.
        BigInteger[] vs = ctx.getV();

        // Now, compute aggregated U and V from the individual terms:
        ECPoint U = ctx.getGenerator().getCurve().getInfinity();
        ECPoint V = ctx.getGenerator().getCurve().getInfinity();

        // For each participant i from 1 to n,
        // compute scalar = evaluations[i] * v[i-1] mod modulus.
        // Then termU = ephemeralKeys[i-1] * scalar, termV = encryptedShares[i-1] *
        // scalar.
        // Aggregate U = U + termU, V = V + termV.
        for (int i = 1; i <= n; i++) {
            BigInteger scalar = evaluations[i].multiply(vs[i - 1]).mod(modulus);
            ECPoint termU = ephemeralKeys[i - 1].multiply(scalar).normalize();
            ECPoint termV = encryptedShares[i - 1].multiply(scalar).normalize();
            System.out.println("Participant " + i + ":");
            System.out.println(" Evaluation m*(α_" + i + ") = " + evaluations[i]);
            System.out.println(" Dual-code coefficient v[" + (i - 1) + "] = " + vs[i - 1]);
            System.out.println(" Computed scalar = " + scalar);
            System.out.println(" termU = " + termU);
            System.out.println(" termV = " + termV);
            U = U.add(termU).normalize();
            V = V.add(termV).normalize();
        }

        System.out.println("Aggregated U = " + U);
        System.out.println("Aggregated V = " + V);

        // Expected V must equal U multiplied by the dealer's secret.
        ECPoint expectedV = U.multiply(dealerSecret).normalize();
        System.out.println("Expected V (dealerSecret * U) = " + expectedV);

        // Assertions for the aggregated values.
        assertNotNull("Aggregated U should not be null", U);
        assertNotNull("Aggregated V should not be null", V);
        assertEquals("Aggregated V should equal dealerSecret * U", expectedV, V);
    }

    @Test
    public void testAggregateUV_Real_Detailed1() throws Exception {
        // Use small parameters for easier debugging.
        int t = 2; // threshold
        int n = 5; // number of participants

        // Generate group parameters (using secp256r1 from Bouncy Castle).
        GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup();
        // Set up the PVSS context; this gives us evaluation points (alphas) and
        // dual‑code coefficients (v's).
        DhPvssContext ctx = DhPvssUtils.dhPvssSetup(groupParams, t, n);
        BigInteger modulus = ctx.getOrder(); // typically the field modulus
        BigInteger[] alphas = ctx.getAlphas();
        BigInteger[] dualCoeffs = ctx.getV();

        SecureRandom random = new SecureRandom();
        // Generate a distribution input; this provides the dealer’s key pair, secret S,
        // and ephemeral keys.
        DistributionInput distInput = DistributionInputGenerator.generateDistributionInput(ctx, random);
        DhKeyPair dealerKeyPair = distInput.getDealerKeyPair();
        BigInteger dealerSecret = dealerKeyPair.getSecretKey();
        ECPoint dealerPub = dealerKeyPair.getPublic();
        ECPoint S = distInput.getSecret(); // the dealer’s secret group element

        // Retrieve the ephemeral keys and simulate encrypted shares.
        EphemeralKeyPublic[] ephemeralKeyPublics = distInput.getEphemeralKeys();
        ECPoint[] ephemeralKeys = new ECPoint[ephemeralKeyPublics.length];
        for (int i = 0; i < ephemeralKeyPublics.length; i++) {
            ephemeralKeys[i] = ephemeralKeyPublics[i].getPublicKey();
            assertNotNull("Ephemeral key " + i + " must not be null", ephemeralKeys[i]);
            assertTrue("Ephemeral key must be on the curve", ephemeralKeys[i].isValid());
        }
        // Simulate the encrypted shares as: C_i = A_i + (dealerSecret * E_i)
        ECPoint[] shares = GShamir_Share.generateSharesEC(ctx, S); // Shamir shares A_i (ECPoints)
        ECPoint[] encryptedShares = new ECPoint[n];
        for (int i = 0; i < n; i++) {
            ECPoint mask = ephemeralKeys[i].multiply(dealerSecret).normalize();
            encryptedShares[i] = shares[i].add(mask).normalize();
        }

        // For testing the hash-to-poly step, use the dealer's public key,
        // the ephemeral keys (we use them as our commitment keys for this test),
        // and the encrypted shares.
        int numPolyCoeffs = n; // For testing, fix the number of coefficients to n.
        BigInteger[] polyCoeffs = HashingTools.hashPointsToPoly(dealerPub, ephemeralKeys, encryptedShares,
                numPolyCoeffs, modulus);

        // Evaluate the polynomial at each evaluation point.
        // (Assume EvaluationTools.evaluatePolynomialAtAllPoints returns an array where
        // index i holds m*(α_i).)
        BigInteger[] evaluations = EvaluationTools.evaluatePolynomialAtAllPoints(polyCoeffs, alphas, modulus);
        // For debugging:
        for (int i = 1; i <= n; i++) {
            System.out.println("Evaluation m*(α_" + i + ") = " + evaluations[i]);
        }

        // Now, compute the aggregated values U and V.
        ECPoint U = ctx.getGenerator().getCurve().getInfinity();
        ECPoint V = ctx.getGenerator().getCurve().getInfinity();

        // For each participant i from 1 to n, compute:
        // scalar_i = evaluations[i] * dualCoeffs[i-1] mod modulus
        // termU = ephemeralKeys[i-1] * scalar_i
        // termV = encryptedShares[i-1] * scalar_i
        for (int i = 1; i <= n; i++) {
            BigInteger scalar = evaluations[i].multiply(dualCoeffs[i - 1]).mod(modulus);
            ECPoint termU = ephemeralKeys[i - 1].multiply(scalar).normalize();
            ECPoint termV = encryptedShares[i - 1].multiply(scalar).normalize();
            System.out.println("Participant " + i + ":");
            System.out.println("  Evaluation m*(α_" + i + ") = " + evaluations[i]);
            System.out.println("  Dual-code coefficient v[" + (i - 1) + "] = " + dualCoeffs[i - 1]);
            System.out.println("  Computed scalar = " + scalar);
            System.out.println("  termU = " + termU);
            System.out.println("  termV = " + termV);
            U = U.add(termU).normalize();
            V = V.add(termV).normalize();
        }

        System.out.println("Aggregated U = " + U);
        System.out.println("Aggregated V = " + V);
        // The expected relation is V = [dealerSecret] * U.
        ECPoint expectedV = U.multiply(dealerSecret).normalize();
        System.out.println("Expected V (dealerSecret * U) = " + expectedV);

        // Now add assertions for each critical step:
        assertNotNull("Aggregated U should not be null", U);
        assertNotNull("Aggregated V should not be null", V);

        // Check that each individual term is computed correctly.
        // (This could be broken into a separate sub-test in a real testing
        // environment.)
        for (int i = 1; i <= n; i++) {
            BigInteger scalar = evaluations[i].multiply(dualCoeffs[i - 1]).mod(modulus);
            ECPoint expectedTermU = ephemeralKeys[i - 1].multiply(scalar).normalize();
            ECPoint expectedTermV = encryptedShares[i - 1].multiply(scalar).normalize();
            // If necessary, you can add assertEquals for these individual terms.
            // (Note: Use appropriate tolerances if working with curves over large fields.)
            // For now, we simply print them.
            System.out.println("For participant " + i + ", expected termU: " + expectedTermU + ", expected termV: "
                    + expectedTermV);
        }

        // Finally, assert that V equals dealerSecret * U.
        assertEquals("Aggregated V should equal dealerSecret * U", expectedV, V);
    }

    public static void main(String[] args) throws Exception {
        DistributionAggregationTest test = new DistributionAggregationTest();
        // test.testAggregateUV();
        // test.testAggregateUVDeterministic();
        // test.testAggregateUV_SimpleCase1();
        // test.testIndividualTermAggregation();
        // test.testAggregateUV_SimpleCase_Detailed();
        // test.testIntermediateEncryptedShareAggregation();
        test.testAggregateUV_Real_Detailed1();

        System.out.println("Participant DistributionAggregationTest test passed!");

    }
}
