package org.example.pvss;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;

public class SSSECTestEC {

    /**
     * Test EC-based Shamir secret sharing reconstruction with a fixed secret.
     */
    @Test
    public void testECSecretSharingReconstruction() {

        int t = 2;
        int n = 5;

        // Generate group parameters over the elliptic curve secp256r1.
        GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup();

        // Call the actual setup function. This internally computes the evaluation
        // points (alphas)
        // as 0, 1, …, n and calculates dual-code coefficients (vs) from the inverse
        // table.
        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(groupParams, t, n);

        assertNotNull("PVSS context should not be null", ctx);

        // For testing, generate a random dealer secret s from [1, subgroupOrder - 1].
        SecureRandom random = new SecureRandom();
        BigInteger p = ctx.getOrder();
        BigInteger s;
        do {
            s = new BigInteger(p.bitLength(), random);
        } while (s.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(p) >= 0);

        // The dealer’s secret EC element S = s·G.
        ECPoint S = ctx.getGenerator().multiply(s).normalize();
        System.out.println("Dealer secret scalar s: " + s);
        System.out.println("Dealer secret S (EC point): " + S);

        // Generate shares using your EC-based Shamir secret sharing.
        ECPoint[] shares = GShamir_Share.generateSharesEC(ctx, S);
        assertNotNull("Shares should not be null", shares);
        System.out.println("Generated Shares:");
        for (int i = 0; i < shares.length; i++) {
            System.out.println("  Share for participant " + (i + 1) + ": " + shares[i]);
        }

        // Reconstruct the secret using a subset of shares (choose participants 1, 2,
        // 3).
        int[] indices = { 1, 2, 3 }; // these correspond to evaluation points α₁, α₂, α₃.
        ECPoint[] subsetShares = new ECPoint[indices.length];
        for (int i = 0; i < indices.length; i++) {
            subsetShares[i] = shares[indices[i] - 1];
        }
        ECPoint S_reconstructed = GShamir_Share.reconstructSecretEC(ctx, subsetShares, indices);
        System.out.println("Reconstructed secret S' (EC point): " + S_reconstructed);

        // Verify that the reconstructed secret matches the original.
        assertEquals("Reconstructed secret should equal the original secret", S, S_reconstructed);
    }

    /**
     * Test that reconstruction is independent of which t+1 shares are chosen by
     * reconstructing the secret using different subsets of shares.
     */
    @Test
    public void testDifferentSubsetsReconstruction() {
        int t = 3; // threshold: degree-3 polynomial, so need 4 shares for reconstruction.
        int n = 7; // total participants.
        GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup();

        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(groupParams, t, n);
        SecureRandom random = new SecureRandom();
        BigInteger p = ctx.getOrder();
        BigInteger s;
        do {
            s = new BigInteger(p.bitLength(), random);
        } while (s.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(p) >= 0);

        ECPoint S = ctx.getGenerator().multiply(s).normalize();
        System.out.println("Dealer secret scalar s: " + s);
        System.out.println("Dealer secret S (EC point): " + S);

        ECPoint[] shares = GShamir_Share.generateSharesEC(ctx, S);
        assertNotNull("Shares should not be null", shares);

        // Define two different subsets of 4 shares.
        int[] indicesSubset1 = { 1, 2, 3, 4 };
        int[] indicesSubset2 = { 3, 4, 5, 6 };

        ECPoint[] subset1 = new ECPoint[indicesSubset1.length];
        for (int i = 0; i < indicesSubset1.length; i++) {
            subset1[i] = shares[indicesSubset1[i] - 1];
        }
        ECPoint reconstructed1 = GShamir_Share.reconstructSecretEC(ctx, subset1, indicesSubset1);
        System.out.println("Reconstructed secret using subset 1: " + reconstructed1);

        ECPoint[] subset2 = new ECPoint[indicesSubset2.length];
        for (int i = 0; i < indicesSubset2.length; i++) {
            subset2[i] = shares[indicesSubset2[i] - 1];
        }
        ECPoint reconstructed2 = GShamir_Share.reconstructSecretEC(ctx, subset2, indicesSubset2);
        System.out.println("Reconstructed secret using subset 2: " + reconstructed2);

        // They must both equal the original secret.
        assertEquals("Subset 1 reconstruction should equal the original", S, reconstructed1);
        assertEquals("Subset 2 reconstruction should equal the original", S, reconstructed2);
    }

    /**
     * Test reconstruction using a larger number of participants.
     * For example, use 200 participants with a threshold of 150.
     */
    @Test
    public void testLargeScaleReconstruction() {
        int t = 150;
        int n = 200;
        GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup();

        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(groupParams, t, n);
        SecureRandom random = new SecureRandom();
        BigInteger p = ctx.getOrder();
        BigInteger s;
        do {
            s = new BigInteger(p.bitLength(), random);
        } while (s.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(p) >= 0);

        ECPoint S = ctx.getGenerator().multiply(s).normalize();
        System.out.println("Large scale test, dealer secret s: " + s);
        System.out.println("Large scale test, dealer secret S: " + S);

        ECPoint[] shares = GShamir_Share.generateSharesEC(ctx, S);
        assertNotNull("Shares should not be null", shares);
        assertEquals("Number of shares should equal n", n, shares.length);

        // Randomly choose t+1 indices from {1,...,n}.
        int k = t + 1;
        int[] indices = new int[k];
        ECPoint[] chosenShares = new ECPoint[k];
        // For simplicity, use the first t+1 shares.
        for (int i = 0; i < k; i++) {
            indices[i] = i + 1;
            chosenShares[i] = shares[i];
        }
        ECPoint reconstructed = GShamir_Share.reconstructSecretEC(ctx, chosenShares, indices);
        System.out.println("Large scale test, reconstructed secret S': " + reconstructed);
        assertEquals("Reconstructed secret should equal the original secret", S, reconstructed);
    }

    public static void main(String[] args) throws Exception {
        SSSECTestEC test = new SSSECTestEC();
        test.testECSecretSharingReconstruction();
        test.testDifferentSubsetsReconstruction();
        test.testLargeScaleReconstruction();
        System.out.println("All EC-based Shamir secret sharing tests passed.");
    }
}
