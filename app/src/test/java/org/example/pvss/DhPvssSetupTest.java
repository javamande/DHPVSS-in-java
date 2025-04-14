package org.example.pvss;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.math.BigInteger;
import java.util.Arrays;

import org.junit.Test;

public class DhPvssSetupTest {

    /**
     * Test the DhPvssSetup function from DhPvssUtils.
     * This test uses the actual group parameters from our GroupGenerator
     * (secp256r1)
     * and verifies that the evaluation points and dual-code coefficients (if
     * computed)
     * are as expected.
     */
    @Test
    public void testDhPvssSetup() {
        // Choose a threshold and number of participants.

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
                    // Generate group parameters (using secp256r1).
                    GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup();

                    // Call the actual setup function. It internally generates evaluation points
                    // (alphas)
                    // as 0, 1, ..., n and computes dual-code coefficients (v) from the inverse
                    // table.
                    DhPvssContext ctx = DhPvssUtils.dhPvssSetup(groupParams, t, n);

                    // Check that the context is non-null.
                    assertNotNull("PVSS context should not be null", ctx);

                    // Check evaluation points.
                    BigInteger[] alphas = ctx.getAlphas();
                    assertNotNull("Evaluation points (alphas) should be computed", alphas);
                    assertEquals("There should be n+1 evaluation points", n + 1, alphas.length);

                    // Check dual-code coefficients.
                    BigInteger[] v = ctx.getV();
                    assertNotNull("Dual-code coefficients should be computed", v);
                    assertEquals("There should be exactly n dual-code coefficients", n, v.length);
                    System.out.println("Test " + i + " out of " + " 10 completet");
                    // Print out the public parameters for manual inspection.
                    System.out.println("=== PVSS Setup Debug ===");
                    System.out.println("Prime modulus p: " + ctx.getOrder());
                    System.out.println("Generator G: " + ctx.getGenerator());
                    System.out.println("Evaluation points (alphas): " + Arrays.toString(alphas));
                    System.out.println("Dual-code coefficients (v): " + Arrays.toString(v));
                    System.out.println("=== End PVSS Setup Debug === " + i + " of 10");
                }
            }
        }

    }

    /**
     * Main method for standalone testing.
     */
    public static void main(String[] args) {
        DhPvssSetupTest test = new DhPvssSetupTest();
        test.testDhPvssSetup();
        System.out.println("PVSS setup test passed!");
    }
}
