package org.example.pvss;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.junit.Test;

public class HashToPolyTest {

    /**
     * Test that the hash-to-poly function returns an array of the expected length.
     * 
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void testHashPointsToPolyLength() throws NoSuchAlgorithmException {
        int maxPartipants = 100;
        for (int i = 1; i <= 10; i++) { // run 10 test with random values of t and n, but always with the property n - t
                                        // - 2 <= 0.
            int t;
            int n;
            do {
                n = (int) (Math.random() * maxPartipants);
                t = (int) (Math.random());
            } while ((n - t - 2) <= 0);

            for (int j = 1; j <= 10; j++) {
                if (i == j) {
                    GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup();

                    DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(groupParams, t, n);
                    // Use our group generator to get the ECPoints.
                    DistributionInput distInput = DistributionInputGenerator.generateDistributionInput(ctx);

                    ECPoint dealerPub = distInput.getDealerKeyPair().getPublic();

                    // Retrieve the list of participant key pairs.
                    EphemeralKeyPublic[] participantKeyPairs = distInput.getEphemeralKeys();

                    // Build an array of ECPoints to be used as the commitment keys.
                    ECPoint[] comKeys = new ECPoint[participantKeyPairs.length];
                    for (int k = 0; k < n; k++) {
                        // For instance, if you want to use each participant’s public key as their
                        // commitment key:
                        comKeys[k] = participantKeyPairs[i - 1].getPublicKey();
                    }
                    ECPoint[] encryptedShares = GShamir_Share.generateSharesEC(ctx, dealerPub);

                    BigInteger modulus = ctx.getOrder();

                    BigInteger[] polyCoeffs = ctx.getAlphas();
                    int numPolyCoeffs = polyCoeffs.length;

                    polyCoeffs = HashingTools.hashPointsToPoly(dealerPub, comKeys, encryptedShares,
                            numPolyCoeffs,
                            modulus);
                    assertNotNull("Polynomial coefficients array must not be null", polyCoeffs);
                    assertEquals("Polynomial coefficients array length", numPolyCoeffs, polyCoeffs.length);
                    System.out.println("Test no " + i + " out of 10 is completed succesfully");
                }
            }
        }

    }

    /**
     * Test that the hash-to-poly function is reproducible.
     */
    @Test
    public void testHashPointsToPolyReproducibility() {
        int maxPartipants = 100;
        for (int i = 1; i <= 10; i++) { // run 10 test with random values of t and n, but always with the property n - t
                                        // - 2 <= 0.
            int t;
            int n;
            do {
                n = (int) (Math.random() * maxPartipants);
                t = (int) (Math.random());
            } while ((n - t - 2) <= 0);

            for (int j = 1; j <= 10; j++) {
                if (i == j) {

                    GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup();

                    DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(groupParams, t, n);

                    // For testing, use fixed ECPoints.
                    ECPoint dealerPub = ctx.getGenerator();
                    // Create arrays of three ECPoints each.
                    ECPoint[] comKeys = new ECPoint[] {
                            ctx.getGenerator().multiply(BigInteger.ONE).normalize(),
                            ctx.getGenerator().multiply(BigInteger.valueOf(2)).normalize(),
                            ctx.getGenerator().multiply(BigInteger.valueOf(3)).normalize()
                    };
                    ECPoint[] encryptedShares = new ECPoint[] {
                            ctx.getGenerator().multiply(BigInteger.valueOf(4)).normalize(),
                            ctx.getGenerator().multiply(BigInteger.valueOf(5)).normalize(),
                            ctx.getGenerator().multiply(BigInteger.valueOf(6)).normalize()
                    };

                    BigInteger modulus = ctx.getOrder();
                    int numPolyCoeffs = 5;
                    BigInteger[] polyCoeffs1 = HashingTools.hashPointsToPoly(dealerPub, comKeys, encryptedShares,
                            numPolyCoeffs,
                            modulus);
                    BigInteger[] polyCoeffs2 = HashingTools.hashPointsToPoly(dealerPub, comKeys, encryptedShares,
                            numPolyCoeffs,
                            modulus);
                    assertArrayEquals("Hash-to-poly must be deterministic", polyCoeffs1, polyCoeffs2);
                    System.out.println("Test no " + i + " out of 10 is completed succesfully");
                }
            }
        }
    }

    @Test
    public void testHashPointsToPolyReproducibility2() throws Exception {

        // In our test, we use the group generator itself as dealerPub.
        // And we create dummy comKeys and encryptedShares by multiplying the generator
        // by fixed scalars.

        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(GroupGenerator.generateGroup(), 2, 5);

        ECPoint dealerPub = ctx.getGenerator();
        ECPoint[] comKeys = new ECPoint[] {
                ctx.getGenerator().multiply(BigInteger.ONE).normalize(),
                ctx.getGenerator().multiply(BigInteger.valueOf(2)).normalize(),
                ctx.getGenerator().multiply(BigInteger.valueOf(3)).normalize()
        };
        ECPoint[] encryptedShares = new ECPoint[] {
                ctx.getGenerator().multiply(BigInteger.valueOf(4)).normalize(),
                ctx.getGenerator().multiply(BigInteger.valueOf(5)).normalize(),
                ctx.getGenerator().multiply(BigInteger.valueOf(6)).normalize()
        };

        BigInteger modulus = ctx.getOrder();
        int numPolyCoeffs = 4;
        BigInteger[] polyCoeffs1 = HashingTools.hashPointsToPoly(dealerPub, comKeys, encryptedShares, numPolyCoeffs,
                modulus);
        BigInteger[] polyCoeffs2 = HashingTools.hashPointsToPoly(dealerPub, comKeys, encryptedShares, numPolyCoeffs,
                modulus);

        assertNotNull("Polynomial coefficients array must not be null", polyCoeffs1);
        assertArrayEquals("Hash-to-poly must be deterministic", polyCoeffs1, polyCoeffs2);

        // Now, test evaluation at one of the evaluation points from the context (say,
        // alpha[2]).
        BigInteger x = ctx.getAlphas()[2]; // Evaluation point for participant 2.
        BigInteger evaluated = EvaluationTools.evaluatePolynomial(polyCoeffs1, x, modulus);

        // For a reproducible test you can compute an expected value manually if you
        // know the seed inputs.
        // For now, print it out for your inspection.
        System.out.println("Polynomial evaluation at alpha[2] = " + evaluated.toString());

        // Optionally, if you have precomputed expected value, assertEquals(expected,
        // evaluated);
    }

    @Test
    public void testHashPointsToPolyAndEvaluation() throws NoSuchAlgorithmException {
        // Use the group from our context. For this test we generate a context using a
        // real EC group.
        GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup();
        int t = 2;
        int n = 5;
        // Set up the PVSS context from our utility; this will generate alphas and
        // dual-code coefficients.
        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(groupParams, t, n);

        // For testing, we pick fixed ECPoints for the dealer's public key, commitment
        // keys, and encrypted shares.
        // In practice, these would be generated as part of the distribution protocol.
        ECPoint dealerPub = ctx.getGenerator(); // For testing, use the generator as a dummy dealer public key.

        // For commitment keys, for example we can use fixed multiples of the generator.
        ECPoint[] comKeys = new ECPoint[] {
                ctx.getGenerator().multiply(BigInteger.ONE).normalize(),
                ctx.getGenerator().multiply(BigInteger.valueOf(2)).normalize(),
                ctx.getGenerator().multiply(BigInteger.valueOf(3)).normalize()
        };
        // For encrypted shares, use other fixed multiples.
        ECPoint[] encryptedShares = new ECPoint[] {
                ctx.getGenerator().multiply(BigInteger.valueOf(4)).normalize(),
                ctx.getGenerator().multiply(BigInteger.valueOf(5)).normalize(),
                ctx.getGenerator().multiply(BigInteger.valueOf(6)).normalize()
        };

        // Choose the number of polynomial coefficients.
        int numPolyCoeffs = 4;
        BigInteger modulus = ctx.getOrder();

        // Compute the polynomial coefficients from the ECPoints.
        BigInteger[] polyCoeffs1 = HashingTools.hashPointsToPoly(dealerPub, comKeys, encryptedShares, numPolyCoeffs,
                modulus);
        BigInteger[] polyCoeffs2 = HashingTools.hashPointsToPoly(dealerPub, comKeys, encryptedShares, numPolyCoeffs,
                modulus);

        // Check that the resulting coefficient arrays are identical (i.e.
        // deterministic).
        assertNotNull("Polynomial coefficients array must not be null", polyCoeffs1);
        assertArrayEquals("Hash-to-poly must be deterministic", polyCoeffs1, polyCoeffs2);

        // Now evaluate the polynomial m*(x) = ∑_{j=0}^{numPolyCoeffs-1} polyCoeffs[j] *
        // x^j mod modulus
        // at all evaluation points stored in the context.
        BigInteger[] evaluations = EvaluationTools.evaluatePolynomialAtAllPoints(polyCoeffs1, ctx.getAlphas(), modulus);

        // For this test, simply print out the evaluations so you can inspect them.
        System.out.println("Evaluation of the polynomial m*(x) at all alpha points:");
        for (int i = 0; i < evaluations.length; i++) {
            System.out.println("  m*(" + ctx.getAlphas()[i] + ") = " + evaluations[i]);
        }
    }

    @Test
    public void testHashPointsToPolyFixedLength() throws NoSuchAlgorithmException {
        // Create a small EC curve for testing. We'll use the secp256r1 curve.
        // (This is the curve used in our GroupGenerator.)
        SecP256R1Curve curve = new SecP256R1Curve();

        // For testing, we create fixed dummy ECPoints on this curve.
        // Note: In practice, these points would come from your protocol.
        // Here, we create some points using small integer values for x and y.
        ECPoint dealerPub = curve.createPoint(BigInteger.valueOf(2), BigInteger.valueOf(3));
        ECPoint[] comKeys = new ECPoint[] {
                curve.createPoint(BigInteger.valueOf(3), BigInteger.valueOf(5)),
                curve.createPoint(BigInteger.valueOf(5), BigInteger.valueOf(7)),
                curve.createPoint(BigInteger.valueOf(7), BigInteger.valueOf(11))
        };
        ECPoint[] encryptedShares = new ECPoint[] {
                curve.createPoint(BigInteger.valueOf(11), BigInteger.valueOf(13)),
                curve.createPoint(BigInteger.valueOf(13), BigInteger.valueOf(17)),
                curve.createPoint(BigInteger.valueOf(17), BigInteger.valueOf(19))
        };

        // Use the curve's field characteristic as the modulus.
        BigInteger modulus = curve.getField().getCharacteristic();
        // For testing, we fix the number of polynomial coefficients to 3.
        int numPolyCoeffs = 3;

        // Call the hashPointsToPoly function twice and ensure reproducibility.
        BigInteger[] polyCoeffs1 = HashingTools.hashPointsToPoly(dealerPub, comKeys, encryptedShares,
                numPolyCoeffs, modulus);
        BigInteger[] polyCoeffs2 = HashingTools.hashPointsToPoly(dealerPub, comKeys, encryptedShares,
                numPolyCoeffs, modulus);

        assertNotNull("Polynomial coefficients array must not be null", polyCoeffs1);
        assertEquals("Polynomial coefficients array length should equal " + numPolyCoeffs,
                numPolyCoeffs, polyCoeffs1.length);

        // Check that repeated calls yield the same coefficients.
        assertArrayEquals("Hash-to-poly must be deterministic", polyCoeffs1, polyCoeffs2);

        // Optionally, print out the computed coefficients for visual inspection.
        System.out.println("Hash-to-poly coefficients:");
        for (int i = 0; i < polyCoeffs1.length; i++) {
            System.out.println("Coefficient[" + i + "] = " + polyCoeffs1[i]);
        }
    }

    public static void main(String[] args) throws Exception {
        HashToPolyTest test = new HashToPolyTest();
        test.testHashPointsToPolyLength();
        test.testHashPointsToPolyReproducibility();

        test.testHashPointsToPolyReproducibility2();
        test.testHashPointsToPolyAndEvaluation();
        test.testHashPointsToPolyFixedLength();
        System.out.println("Participant HashTOPoly test passed!");
    }
}
