package org.example.pvss;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;

import java.util.Arrays;

import org.bouncycastle.math.ec.ECPoint;
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
                    DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(groupParams, t, n);

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

    /** 1. Valid setup with fixed parameters. */
    @Test
    public void testFixedSetup() {
        int t = 2, n = 5;
        GroupGenerator.GroupParameters gp = GroupGenerator.generateGroup();
        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(gp, t, n);

        // Basic non-null checks
        assertNotNull(ctx);
        assertNotNull(ctx.getOrder());
        assertNotNull(ctx.getGenerator());

        // Array lengths
        BigInteger[] alphas = ctx.getAlphas();
        assertEquals("alphas.length == n+1", n + 1, alphas.length);
        assertEquals("alphas[0] == 0", BigInteger.ZERO, alphas[0]);

        BigInteger[] v = ctx.getV();
        assertEquals("v.length == n", n, v.length);
    }

    /** 2. SCRAPE dual‑code identity in the scalar field. */
    @Test
    public void testDualCodeIdentity() {
        int t = 2, n = 5;
        GroupGenerator.GroupParameters gp = GroupGenerator.generateGroup();
        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(gp, t, n);

        BigInteger p = ctx.getOrder();
        BigInteger[] alphas = ctx.getAlphas();
        BigInteger[] v = ctx.getV();

        int maxK = n - t - 1;
        for (int k = 0; k <= maxK; k++) {
            BigInteger sum = BigInteger.ZERO;
            for (int i = 1; i <= n; i++) {
                BigInteger pow = alphas[i].modPow(BigInteger.valueOf(k), p);
                sum = sum.add(v[i - 1].multiply(pow)).mod(p);
            }
            assertEquals(
                    String.format("Σ v_i·α_i^%d mod p", k),
                    BigInteger.ZERO, sum);
        }
    }

    /** 3. Invalid parameters should throw. */
    @Test(expected = IllegalArgumentException.class)
    public void testInvalidParamsTooSmall() {
        // Here n - t - 2 <= 0, e.g. t=4, n=5 => 5-4-2 = -1
        GroupGenerator.GroupParameters gp = GroupGenerator.generateGroup();
        DHPVSS_Setup.dhPvssSetup(gp, /* t= */4, /* n= */5);
    }

    /** 4. Randomized smoke test for various (t,n). */
    @Test
    public void testRandomizedParams() {
        final int ROUNDS = 10, MAX_N = 12;
        for (int round = 0; round < ROUNDS; round++) {
            int n, t;
            do {
                n = 3 + (int) (Math.random() * (MAX_N - 2)); // n >= 3
                t = (int) (Math.random() * (n - 2)); // 0 <= t <= n-3
            } while (n - t - 2 <= 0);

            GroupGenerator.GroupParameters gp = GroupGenerator.generateGroup();
            DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(gp, t, n);

            // spot check lengths
            assertEquals(n + 1, ctx.getAlphas().length);
            assertEquals(n, ctx.getV().length);

            // spot check dual-code identity for k=0 only
            BigInteger p = ctx.getOrder();
            BigInteger sum = BigInteger.ZERO;
            for (int i = 1; i <= n; i++) {
                sum = sum.add(ctx.getV()[i - 1]).mod(p);
            }
            assertEquals("Round " + round + " dual-code k=0", BigInteger.ZERO, sum);
        }
    }

    @Test
    public void testDualPrimalMonomialOrthogonality() {
        int t = 2, n = 5;
        // 1) setup
        GroupGenerator.GroupParameters gp = GroupGenerator.generateGroup();
        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(gp, t, n);

        BigInteger p = ctx.getOrder();
        BigInteger[] alphas = ctx.getAlphas();
        BigInteger[] v = ctx.getV();

        // 2) for each primal basis j=0..t and each dual basis k=0..(n-t-1),
        // check sum_{i=1}^n (alpha_i^k) * (alpha_i^j) * v_i == 0 mod p
        for (int j = 0; j <= t; j++) {
            for (int k = 0; k <= n - t - 2; k++) {
                BigInteger sum = BigInteger.ZERO;
                for (int i = 1; i <= n; i++) {
                    BigInteger ai = alphas[i].mod(p);
                    BigInteger primal = ai.modPow(BigInteger.valueOf(j), p);
                    BigInteger dual = ai.modPow(BigInteger.valueOf(k), p);
                    BigInteger term = v[i - 1].multiply(primal).multiply(dual).mod(p);
                    sum = sum.add(term).mod(p);
                }
                assertEquals(
                        String.format("⟨dual^%d, primal^%d⟩ failed", k, j),
                        BigInteger.ZERO,
                        sum);
            }
        }
    }

    @Test
    public void testScrapeCoefficientsAndDualCodeIdentity() {
        int t = 2, n = 5;
        GroupGenerator.GroupParameters gp = GroupGenerator.generateGroup();
        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(gp, t, n);

        BigInteger p = ctx.getOrder();
        BigInteger[] alphas = ctx.getAlphas();
        BigInteger[] vCtx = ctx.getV();

        // 1) Compute vDirect[i] = ∏_{j≠i} (α_i - α_j)^{-1} mod p
        BigInteger[] vDirect = new BigInteger[n];
        for (int i = 1; i <= n; i++) {
            BigInteger prod = BigInteger.ONE;
            for (int j = 1; j <= n; j++) {
                if (i == j)
                    continue;
                BigInteger diff = alphas[i].subtract(alphas[j]).mod(p);
                BigInteger inv = diff.modInverse(p);
                prod = prod.multiply(inv).mod(p);
            }
            vDirect[i - 1] = prod;
        }

        // 2) Assert they match your implementation
        for (int i = 0; i < n; i++) {
            assertEquals(
                    String.format("v[%d] mismatch: direct vs ctx", i + 1),
                    vDirect[i], vCtx[i]);
        }

        // 3) Now rerun the full dual‐code identity with vDirect
        // for each k = 0 ... (n - t - 1), Σ v_i·α_i^k ≡ 0 mod p
        int maxK = n - t - 1;
        for (int k = 0; k <= maxK; k++) {
            BigInteger sum = BigInteger.ZERO;
            for (int i = 1; i <= n; i++) {
                BigInteger pow = alphas[i].modPow(BigInteger.valueOf(k), p);
                sum = sum.add(vDirect[i - 1].multiply(pow)).mod(p);
            }
            assertEquals(
                    String.format("Dual-code identity failed at k=%d", k),
                    BigInteger.ZERO, sum);
        }
    }

    // Helper: performs the SCRAPE aggregation Σ v_i·m*(α_i)·A_i and returns the
    // ECPoint T.
    private ECPoint scrapeAggregate(
            DhPvssContext ctx,
            ECPoint[] shares,
            BigInteger c1 // challenge polynomial m*(X) = c1·X
    ) {
        BigInteger p = ctx.getOrder();
        ECPoint G = ctx.getGenerator();
        BigInteger[] alphas = ctx.getAlphas();
        BigInteger[] v = ctx.getV();

        ECPoint T = G.getCurve().getInfinity();
        for (int i = 1; i <= shares.length; i++) {
            BigInteger mStar = c1.multiply(alphas[i]).mod(p);
            BigInteger scalar = v[i - 1].multiply(mStar).mod(p);
            T = T.add(shares[i - 1].multiply(scalar));
        }
        return T;
    }

    @Test
    public void testScrapeDetectsTampering() {
        // Setup
        int t = 2, n = 5;
        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(
                GroupGenerator.generateGroup(), t, n);

        // Dealer secret
        BigInteger secretScalar = BigInteger.valueOf(7).mod(ctx.getOrder());
        ECPoint S = ctx.getGenerator().multiply(secretScalar);

        // Build correct shares: A_i = S + m(α_i)*G with m(X)=11+17X+23X^2
        BigInteger a0 = BigInteger.valueOf(11),
                a1 = BigInteger.valueOf(17),
                a2 = BigInteger.valueOf(23);
        ECPoint[] shares = new ECPoint[n];
        BigInteger p = ctx.getOrder();
        for (int i = 1; i <= n; i++) {
            BigInteger xi = ctx.getAlphas()[i].mod(p);
            BigInteger mi = a0
                    .add(a1.multiply(xi))
                    .add(a2.multiply(xi.pow(2)))
                    .mod(p);
            shares[i - 1] = S.add(ctx.getGenerator().multiply(mi));
        }

        // Challenge poly m*(X)=3·X
        BigInteger c1 = BigInteger.valueOf(3).mod(p);

        // 1) Confirm the untampered aggregation is infinity
        ECPoint T0 = scrapeAggregate(ctx, shares, c1);
        assertTrue("SCRAPE should pass on valid shares", T0.isInfinity());

        // 2) Tamper one share and confirm SCRAPE now fails
        shares[2] = shares[2].add(ctx.getGenerator()); // add one G
        ECPoint T1 = scrapeAggregate(ctx, shares, c1);
        assertFalse("SCRAPE must detect a tampered share", T1.isInfinity());
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
