package org.example.pvss;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.math.BigInteger;

import org.junit.Test;

public class SSSTest {

    /**
     * Tests the DhPvssSetup function to ensure that the context (including
     * evaluation points and dual-code
     * coefficients) is correctly computed, and then uses that context for Shamir
     * secret sharing and reconstruction.
     */
    @Test
    public void testSetupAndReconstruction() {
        // Use a small lambda for testing.
        int lambda = 32; // security parameter (small for testing)
        int t = 2; // threshold: polynomial degree is 2 (requires t+1 = 3 shares to reconstruct)
        int n = 5; // total number of participants

        // Generate group parameters and then the PVSS context using the setup function.
        GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup(lambda);
        DhPvssContext ctx = DhPvssUtils.dhPvssSetup(groupParams, t, n);

        System.out.println("Prime Order p = " + ctx.getOrder());
        System.out.println("Group generator G = " + ctx.getGenerator());
        // Verify that the context is not null and that the evaluation points and
        // dual-code coefficients are computed.
        assertNotNull("PVSS context should not be null", ctx);
        assertNotNull("Evaluation points should be computed", ctx.getAlphas());
        assertNotNull("Dual-code coefficients should be computed", ctx.getV());

        // For debugging, print out the evaluation points and dual-code coefficients.
        System.out.println("Evaluation points (alphas):");
        for (BigInteger alpha : ctx.getAlphas()) {
            System.out.println("  " + alpha);
        }
        System.out.println("Dual-code coefficients (vs):");
        for (BigInteger v : ctx.getV()) {
            System.out.println("  " + v);
        }

        // Define a test secret. In the additive formulation, the secret is a group
        // element.
        // For testing, we can treat it as a scalar.
        BigInteger secret = BigInteger.valueOf(7);
        BigInteger S = ctx.getGenerator().modPow(secret, ctx.getOrder());

        // Generate shares using your Shamir secret sharing function.
        BigInteger[] shares = SSSStandard.generateSharesStandard(ctx, S);
        assertNotNull("Shares should not be null", shares);
        assertEquals("Number of shares should equal n", n, shares.length);

        System.out.println("Shares Ai, from SSS are: " + shares);

        // For reconstruction, select t+1 shares.
        int[] indices = { 1, 2, 3 }; // using participants 1,2,3 (you could choose any t+1 indices)
        BigInteger[] selectedShares = new BigInteger[indices.length];
        for (int i = 0; i < indices.length; i++) {
            // shares are stored at index (participant index - 1)
            selectedShares[i] = shares[indices[i] - 1];
        }

        // Reconstruct the secret using your reconstruction function.
        BigInteger reconstructed = SSSStandard.reconstructSecretStandard(ctx, selectedShares, indices);

        // Debug output for reconstruction.
        System.out.println("Original secret:      " + S);
        System.out.println("Reconstructed secret: " + reconstructed);

        // The reconstructed secret should match the original secret.
        assertEquals("Reconstructed secret should equal the original secret", S, reconstructed);
    }

    public static void main(String[] args) throws Exception {
        SSSTest test = new SSSTest();
        test.testSetupAndReconstruction();

        System.out.println("All Shamir secret sharing tests passed!");
    }
}
