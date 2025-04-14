package org.example.pvss;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;

public class DistributionInputTest {

    @Test
    public void testDistributionInputGeneration() throws Exception {
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

                    // Generate the distribution input.
                    DistributionInput input = DistributionInputGenerator.generateDistributionInput(ctx, random);
                    assertNotNull("Distribution input must not be null", input);

                    // Check dealer key pair.
                    assertNotNull("Dealer key pair must not be null", input.getDealerKeyPair());
                    assertNotNull("Dealer public key must not be null", input.getDealerKeyPair().getPublic());

                    // Check ephemeral keys.
                    EphemeralKeyPublic[] ephemeralKeys = input.getEphemeralKeys();
                    assertNotNull("Ephemeral keys array must not be null", ephemeralKeys);
                    assertEquals("There should be exactly " + n + " ephemeral keys", n, ephemeralKeys.length);
                    for (int k = 0; k < ephemeralKeys.length; k++) {
                        EphemeralKeyPublic ek = ephemeralKeys[k];
                        assertNotNull("Ephemeral key public part must not be null", ek.getPublicKey());
                        // Optionally, check that each key is on the curve.
                        assertTrue("Ephemeral key must be on the curve", ek.getPublicKey().isValid());
                        // Optionally, check that the associated proof is not null.
                        assertNotNull("Ephemeral key proof must not be null", ek.getProof());
                    }

                    // Check secret.
                    ECPoint secret = input.getSecret();
                    assertNotNull("Secret must not be null", secret);

                    System.out.println("Distribution input generated successfully:");
                    System.out.println("Dealer public key: " + input.getDealerKeyPair().getPublic());
                    System.out.println("Ephemeral keys: " + Arrays.toString(Arrays.stream(ephemeralKeys)
                            .map(EphemeralKeyPublic::getPublicKey)
                            .toArray(ECPoint[]::new)));
                    System.out.println("Secret: " + secret);
                    System.out.println("Test " + i + " of 10 Complete!");
                }
            }

        }
    }

    public static void main(String[] args) throws Exception {
        // Run the test as a standalone application.
        DistributionInputTest test = new DistributionInputTest();
        test.testDistributionInputGeneration();
        System.out.println("All DistributionInputTest tests passed!");
    }
}