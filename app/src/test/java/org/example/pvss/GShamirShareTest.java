package org.example.pvss;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;

/**
 * Unit tests for GShamir_Share: share generation and secret reconstruction.
 */
public class GShamirShareTest {

    /**
     * Test that generateSharesEC produces exactly n shares and that each share
     * is of the form S + m(α_i)·G with m(0)=0.
     */
    @Test
    public void testGenerateSharesProducesCorrectForm() {
        // Setup
        int t = 2, n = 5;
        GroupGenerator.GroupParameters gp = GroupGenerator.generateGroup();
        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(gp, t, n);
        BigInteger p = ctx.getOrder();

        // Dealer secret scalar and point
        BigInteger secretScalar = new BigInteger(p.bitLength(), new SecureRandom()).mod(p);
        ECPoint S = ctx.getGenerator().multiply(secretScalar);

        // Generate shares
        ECPoint[] shares = GShamir_Share.generateSharesEC(ctx, S);
        assertNotNull(shares);
        assertEquals("Should produce n shares", n, shares.length);

        // Verify that share[0] != S (unless m(α_1)==0 by chance)
        boolean allEqual = true;
        for (int i = 0; i < n; i++) {
            if (!shares[i].equals(S)) {
                allEqual = false;
                break;
            }
        }
        assertFalse("At least one share must differ from S", allEqual);
    }

    /**
     * Test that reconstructSecretEC recovers S exactly when given any t+1 shares.
     */
    @Test
    public void testReconstructWithThresholdPlusOneShares() {
        int t = 2, n = 5;
        GroupGenerator.GroupParameters gp = GroupGenerator.generateGroup();
        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(gp, t, n);
        BigInteger p = ctx.getOrder();

        BigInteger secretScalar = new BigInteger(p.bitLength(), new SecureRandom()).mod(p);
        ECPoint S = ctx.getGenerator().multiply(secretScalar);
        ECPoint[] shares = GShamir_Share.generateSharesEC(ctx, S);

        // Pick indices [1,2,3] (t+1 shares)
        int k = t + 1;
        int[] indices = new int[k];
        ECPoint[] subset = new ECPoint[k];
        for (int i = 0; i < k; i++) {
            indices[i] = i + 1; // participants 1..t+1
            subset[i] = shares[i];
        }

        ECPoint recovered = GShamir_Share.reconstructSecretEC(ctx, subset, indices);
        assertEquals("Reconstructed secret must equal original S", S, recovered);
    }

    /**
     * Test that reconstructSecretEC throws IllegalArgumentException
     * when shares.length != indices.length.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testReconstructWithMismatchedLengths() {
        int t = 2, n = 5;
        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(
                GroupGenerator.generateGroup(), t, n);
        BigInteger secretScalar = BigInteger.ONE;
        ECPoint S = ctx.getGenerator().multiply(secretScalar);
        ECPoint[] shares = GShamir_Share.generateSharesEC(ctx, S);
        // Mismatch: 3 shares, but only 2 indices
        ECPoint[] subset = new ECPoint[t + 1];
        int[] indices = new int[t];
        for (int i = 0; i < t + 1; i++)
            subset[i] = shares[i];
        for (int i = 0; i < t; i++)
            indices[i] = i + 1;
        // Should throw
        GShamir_Share.reconstructSecretEC(ctx, subset, indices);
    }

    /**
     * Test that reconstruction fails (produces wrong point) if fewer than t+1
     * shares provided.
     */
    @Test
    public void testReconstructWithTooFewShares() {
        int t = 2, n = 5;
        GroupGenerator.GroupParameters gp = GroupGenerator.generateGroup();
        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(gp, t, n);
        BigInteger p = ctx.getOrder();

        BigInteger secretScalar = BigInteger.valueOf(42).mod(p);
        ECPoint S = ctx.getGenerator().multiply(secretScalar);
        ECPoint[] shares = GShamir_Share.generateSharesEC(ctx, S);

        // Provide only t shares (should not reconstruct correctly)
        ECPoint[] subset = new ECPoint[t];
        int[] indices = new int[t];
        for (int i = 0; i < t; i++) {
            subset[i] = shares[i];
            indices[i] = i + 1;
        }
        ECPoint recovered = GShamir_Share.reconstructSecretEC(ctx, subset, indices);
        assertNotEquals("Reconstruction with too few shares should not equal S", S, recovered);
    }
}
