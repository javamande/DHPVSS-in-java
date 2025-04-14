package org.example.pvss;

import static org.junit.Assert.assertTrue;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.junit.Test;

public class DLProofTest1 {

    @Test
    public void testDLProofVerification() throws NoSuchAlgorithmException {

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
                    // Generate the group parameters for secp256r1 using your GroupGenerator.
                    GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup();
                    // Set up the PVSS context using your helper method.
                    // This call uses your existing DhPvssUtils.dhPvssSetup implementation.
                    DhPvssContext ctx = DhPvssUtils.dhPvssSetup(groupParams, t, n);
                    // Note: The context now contains the elliptic curve group parameters
                    // (generator,
                    // prime modulus, evaluation points, etc.)

                    // Generate a key pair using the context and a source of randomness.
                    SecureRandom random = new SecureRandom();
                    DhKeyPair keyPair = DhKeyPair.generate(ctx, random);

                    // Generate the DL proof using the generated key pair.
                    NizkDlProof proof = NizkDlProofGenerator.generateProof(ctx, keyPair);

                    // Verify the proof using the public key from the key pair.
                    boolean valid = NizkDLProofVerificator.verifyProof(ctx, keyPair.getPublic(), proof);

                    // Debug output (if desired):
                    System.out.println("DL proof verification passed: " + valid + " for " + i + " of 10");

                    // Assert that the proof verifies.
                    assertTrue("DL proof verification should pass", valid);
                }
            }
        }

    }

    public static void main(String[] args) throws Exception {
        // Run the test as a standalone application.
        DLProofTest1 test = new DLProofTest1();
        test.testDLProofVerification();
        System.out.println("All DL proof tests passed!");
    }
}
