package org.example.pvss;

import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;

public class DLEQProofTest {

    /**
     * Tests that the DLEQ proof generated during distribution (via the distribution
     * input
     * generator) verifies correctly.
     *
     * This test assumes that the distribution input generator creates a container
     * object
     * (of type DHPVSSDistributionInput) that includes:
     * - The dealer's key pair (containing the secret key and the corresponding
     * public key).
     * - The weighted aggregate value U (derived from the commitment keys).
     * - The weighted aggregate value V (computed from the encrypted shares).
     * - The DLEQ proof that asserts the relation V = U^(sk_D) (i.e. the same
     * exponent was used
     * for both computations).
     */
    @Test
    public void testDLEQProofFromDistributionInput() throws Exception {

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
                    // Set up the PVSS context using your helper method.
                    // This call uses your existing DhPvssUtils.dhPvssSetup implementation.
                    DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(groupParams, t, n);
                    // Note: The context now contains the elliptic curve group parameters
                    // (generator,
                    // prime modulus, evaluation points, etc.)

                    // Generate a key pair using the context and a source of randomness.
                    SecureRandom random = new SecureRandom();

                    // Generate the distribution input (dealer's key pair, participant key pairs,
                    // and secret S).
                    DistributionInput input = DistributionInputGenerator.generateDistributionInput(ctx,
                            random);
                    // Extract the components needed for the DLEQ proof.
                    DhKeyPair dealerKeyPair = input.getDealerKeyPair();
                    // In the distribution protocol, the DLEQ proof shows that:
                    // V = U^(dealerSecret) mod p,
                    // where U is computed as the weighted product of the commitment keys and V as
                    // that of the encrypted shares.
                    // We assume that your distribution input generator provides the weighted sums U
                    // and V.
                    ECPoint G = ctx.getGenerator();
                    ECPoint pkD = dealerKeyPair.getPublic();
                    BigInteger skD = dealerKeyPair.getSecretKey();
                    // Use our group generator to get the ECPoints.
                    DistributionInput distInput = DistributionInputGenerator.generateDistributionInput(ctx, random);

                    ECPoint dealerPub = distInput.getDealerKeyPair().getPublic();

                    ECPoint S = distInput.getSecret();

                    // Retrieve the list of participant key pairs.
                    List<DhKeyPair> participantKeyPairs = distInput.getParticipantKeyPairs();

                    // Build an array of ECPoints to be used as the commitment keys.
                    ECPoint[] comKeys = new ECPoint[participantKeyPairs.size()];
                    for (int k = 0; k < participantKeyPairs.size(); k++) {
                        // For instance, if you want to use each participant’s public key as their
                        // commitment key:
                        comKeys[k] = participantKeyPairs.get(k).getPublic();
                    }
                    ECPoint[] encryptedShares = GShamir_Share.generateSharesEC(ctx, S);

                    BigInteger modulus = ctx.getGroupParameters().getN();

                    BigInteger[] polyCoeffs = ctx.getAlphas();
                    int numPolyCoeffs = polyCoeffs.length;
                    BigInteger[] vis = ctx.getV();
                    polyCoeffs = HashingTools.hashPointsToPoly(dealerPub, comKeys, encryptedShares,
                            numPolyCoeffs,
                            modulus);

                    ECPoint[] UV = DistributionAggregation.aggregateUV(polyCoeffs, polyCoeffs, vis, comKeys,
                            encryptedShares,
                            modulus);
                    ECPoint U = UV[0];
                    ECPoint V = UV[1];
                    // Generate the DLEQ proof that proves the relation:
                    // pk_D = [skD]G and V = [skD]U.
                    NizkDlEqProof proof = NizkDlEqProof.generateProof(ctx, U, pkD, V, skD);
                    // Verify the proof.
                    boolean valid = NizkDlEqProof.verifyProof(ctx, U, pkD, V, proof);

                    System.out.println("DLEQ proof verification result: " + valid + " for " + i + " of 10");
                    // Assert that the proof verifies.
                    assertTrue("The DLEQ proof from the distribution input should verify", valid);
                }

            }
        }
    }

    public static void main(String[] args) throws Exception {
        new DLEQProofTest().testDLEQProofFromDistributionInput();
        System.out.println("DLEQ proof test with distribution input passed!");
    }
}
