package org.example.pvss;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;

public class DhKeyPairGenerationTest {

    /**
     * Tests that the key generation method correctly computes a key pair.
     * The public key should equal the group generator multiplied by the secret key.
     */
    @Test
    public void testKeyGeneration() {
        // Use your setup function to create a PVSS context.
        // For example, choose threshold t and total participants n.
        int maxPartipants = 15;
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

                    // Generate group parameters from the GroupGenerator (using secp256r1).
                    GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup();
                    DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(groupParams, t, n);

                    // Check that the context is non-null.
                    assertNotNull("PVSS context should not be null", ctx);

                    // Initialize a secure random source.
                    SecureRandom random = new SecureRandom();

                    // Generate a key pair using the PVSS context.
                    DhKeyPair keyPair = DhKeyPair.generate(ctx, random);

                    // Print out debugging information.
                    System.out.println("=== Key Generation Debug ===");
                    System.out.println("Generated secret key (scalar s): " + keyPair.getSecretKey());
                    System.out.println("Generated public key: " + keyPair.getPublic());

                    // Calculate the expected public key:
                    // In elliptic curve groups using additive notation, the public key should be G
                    // * secret.
                    ECPoint expectedPub = ctx.getGenerator().multiply(keyPair.getSecretKey()).normalize();
                    System.out.println("Expected public key (G * s): " + expectedPub);

                    // Assert that the computed public key equals the expected one.
                    assertEquals("The generated public key must equal G * secretKey", expectedPub, keyPair.getPublic());
                    System.out.println("=== Key Generation Test Passed ===" + i + " of 10");
                }

            }
        }
    }

    /**
     * Standalone main method to run the key generation test.
     */

    public static void main(String[] args) throws Exception {
        DhKeyPairGenerationTest test = new DhKeyPairGenerationTest();
        test.testKeyGeneration();
        System.out.println("Key Generation Test Passed!");
    }

}
