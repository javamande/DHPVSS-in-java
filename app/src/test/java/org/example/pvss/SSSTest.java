package org.example.pvss;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.junit.Test;

public class SSSTest {

    /**
     * Creates a DhPvssContext using your dhPvssSetup function.
     * This context already contains the evaluation points (alphas) and dual‑code
     * coefficients.
     *
     * @param lambda security parameter (bits)
     * @param t      threshold
     * @param n      total number of participants
     * @return a DhPvssContext instance with public parameters computed by
     *         dhPvssSetup.
     */
    private DhPvssContext createContext(int lambda, int t, int n) {
        GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup(lambda);
        return DhPvssUtils.dhPvssSetup(groupParams, t, n);
    }

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
        DhPvssContext ctx = createContext(lambda, t, n);

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

    // * Test reconstruction using a larger prime.
    // * Uses a 64-bit security parameter.
    // */
    @Test
    public void testReconstructionLargePrime() {
        int lambda = 64; // Larger security parameter for a larger prime.
        int t = 3; // Degree t polynomial requires t+1 = 4 shares for reconstruction.
        int n = 7; // Total number of participants.
        DhPvssContext ctx = createContext(lambda, t, n);
        BigInteger p = ctx.getOrder();

        // For testing, choose a fixed secret scalar.
        BigInteger secretScalar = new BigInteger("123456789");
        // In the multiplicative setting, encode the secret as S = G^(secretScalar) mod
        // p.
        BigInteger S = ctx.getGenerator().modPow(secretScalar, p);

        // Generate shares using the standard Shamir secret sharing function.
        BigInteger[] shares = SSSStandard.generateSharesStandard(ctx, S);
        assertNotNull("Shares should not be null", shares);
        assertEquals("Number of shares should equal n", n, shares.length);

        // Reconstruct using t+1 shares (e.g., participants 1, 2, 3, 4).
        int[] indices = { 1, 2, 3, 4 };
        BigInteger[] selectedShares = new BigInteger[indices.length];
        for (int i = 0; i < indices.length; i++) {
            // Shares are stored at index (participant index - 1)
            selectedShares[i] = shares[indices[i] - 1];
        }
        BigInteger reconstructed = SSSStandard.reconstructSecretStandard(ctx, selectedShares, indices);
        System.out.println("Original secret S: " + S);
        System.out.println("Reconstructed secret: " + reconstructed);
        assertEquals("Reconstructed secret should equal the original secret", S, reconstructed);
    }

    /**
     * Test reconstruction with random secrets over a larger prime.
     * Runs multiple iterations to ensure consistency.
     */
    @Test
    public void testReconstructionRandomSecrets() {
        int lambda = 64;
        int t = 2;
        int n = 5;
        DhPvssContext ctx = createContext(lambda, t, n);
        BigInteger p = ctx.getOrder();
        SecureRandom rnd = new SecureRandom();

        for (int i = 0; i < 10; i++) {
            BigInteger secretScalar = new BigInteger(p.bitLength() - 1, rnd);
            BigInteger S = ctx.getGenerator().modPow(secretScalar, p);
            BigInteger[] shares = SSSStandard.generateSharesStandard(ctx, S);
            int[] indices = { 1, 2, 3 }; // t+1 shares
            BigInteger[] selectedShares = new BigInteger[indices.length];
            for (int j = 0; j < indices.length; j++) {
                selectedShares[j] = shares[indices[j] - 1];
            }
            BigInteger reconstructed = SSSStandard.reconstructSecretStandard(ctx, selectedShares, indices);
            System.out.println("Iteration " + (i + 1) + ":");
            System.out.println("  Secret S: " + S);
            System.out.println("  Reconstructed: " + reconstructed);
            assertEquals("Random secret reconstruction should match", S, reconstructed);
        }
    }

    /**
     * Test that different subsets of t+1 shares yield the same secret.
     */
    @Test
    public void testDifferentSubsetsReconstruction() {
        int lambda = 64;
        int t = 3;
        int n = 7;
        DhPvssContext ctx = createContext(lambda, t, n);
        BigInteger p = ctx.getOrder();
        SecureRandom rnd = new SecureRandom();

        BigInteger secretScalar = new BigInteger(p.bitLength() - 1, rnd);
        BigInteger S = ctx.getGenerator().modPow(secretScalar, p);
        BigInteger[] shares = SSSStandard.generateSharesStandard(ctx, S);

        // Use two different subsets of t+1 shares.
        int[] indices1 = { 1, 2, 3, 4 };
        int[] indices2 = { 2, 3, 4, 5 };
        BigInteger[] subset1 = new BigInteger[indices1.length];
        BigInteger[] subset2 = new BigInteger[indices2.length];
        for (int i = 0; i < indices1.length; i++) {
            subset1[i] = shares[indices1[i] - 1];
        }
        for (int i = 0; i < indices2.length; i++) {
            subset2[i] = shares[indices2[i] - 1];
        }
        BigInteger rec1 = SSSStandard.reconstructSecretStandard(ctx, subset1, indices1);
        BigInteger rec2 = SSSStandard.reconstructSecretStandard(ctx, subset2, indices2);
        System.out.println("Reconstruction from subset 1: " + rec1);
        System.out.println("Reconstruction from subset 2: " + rec2);
        assertEquals("Both reconstructions should yield the same secret", rec1, rec2);
        assertEquals("Reconstructed secret should match original", S, rec1);
    }

    @Test
    public void testReconstructionLargeParticipants() {
        int lambda = 128; // Use a 128-bit security parameter for a larger prime.
        int t = 150; // Threshold: degree t polynomial (requires t+1 shares for reconstruction).
        int n = 200; // Total number of participants.

        // Create the PVSS context using the already computed evaluation points and
        // dual-code coefficients.
        DhPvssContext ctx = createContext(lambda, t, n);
        BigInteger p = ctx.getOrder();
        SecureRandom rnd = new SecureRandom();

        // Generate a random secret scalar.
        BigInteger secretScalar = new BigInteger(p.bitLength() - 1, rnd);
        // Encode the secret in the multiplicative setting: S = G^(secretScalar) mod p.
        BigInteger S = ctx.getGenerator().modPow(secretScalar, p);

        // Generate shares using your Shamir secret sharing function.
        BigInteger[] shares = SSSStandard.generateSharesStandard(ctx, S);
        assertNotNull("Shares should not be null", shares);
        assertEquals("Number of shares should equal n", n, shares.length);

        // Randomly select t+1 (i.e., 151) distinct indices from {1, 2, ..., n}.
        int tPlusOne = t + 1;
        Integer[] indicesArr = new Integer[n];
        for (int i = 0; i < n; i++) {
            indicesArr[i] = i + 1; // Evaluation points for participants 1,...,n.
        }
        // Shuffle the indices array.
        java.util.Collections.shuffle(java.util.Arrays.asList(indicesArr), rnd);
        int[] indices = new int[tPlusOne];
        BigInteger[] selectedShares = new BigInteger[tPlusOne];
        for (int i = 0; i < tPlusOne; i++) {
            indices[i] = indicesArr[i];
            // Shares are stored at index (participant index - 1)
            selectedShares[i] = shares[indices[i] - 1];
        }

        // Reconstruct the secret using the selected shares.
        BigInteger reconstructed = SSSStandard.reconstructSecretStandard(ctx, selectedShares, indices);
        System.out.println("Test with 200 participants and threshold 150:");
        System.out.println("  Original secret S: " + S);
        System.out.println("  Reconstructed secret: " + reconstructed);

        // The reconstructed secret should match the original secret.
        assertEquals("Reconstructed secret should equal the original secret", S, reconstructed);
    }

    public static void main(String[] args) throws Exception {
        SSSTest test = new SSSTest();
        test.testSetupAndReconstruction();
        test.testReconstructionLargePrime();
        test.testReconstructionRandomSecrets();
        test.testDifferentSubsetsReconstruction();
        test.testReconstructionLargeParticipants();
        System.out.println("All Shamir secret sharing tests passed!");
    }
}
