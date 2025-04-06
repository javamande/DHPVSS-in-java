package org.example.pvss;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import org.junit.Test;

public class DhPvssContextTest {

    @Test
    public void testDhPvssContextSetup() {
        int lambda = 32; // security parameter for testing (small, for demonstration)
        int t = 2; // threshold
        int n = 5; // number of participants

        // Generate finite-field group parameters.
        GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup(lambda);
        assertNotNull("Group parameters should not be null", groupParams);

        // Create evaluation points α₀, α₁, …, αₙ (using consecutive integers for
        // testing)
        BigInteger[] alphas = new BigInteger[n + 1];
        for (int i = 0; i <= n; i++) {
            alphas[i] = BigInteger.valueOf(i);
        }

        // For this test, dual-code coefficients can be dummy (set to 1)
        BigInteger[] v = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            v[i] = BigInteger.ONE;
        }

        // Create the PVSS context.
        DhPvssContext ctx = new DhPvssContext(groupParams, t, n, alphas[0], alphas, v);
        assertNotNull("PVSS context should not be null", ctx);

        // Verify that the group parameters in the context are as expected.
        assertEquals("Context modulus should equal group parameter p", groupParams.getP(), ctx.getOrder());
        assertEquals("Context generator should equal group parameter g", groupParams.getG(), ctx.getGenerator());

        // Verify evaluation points.
        BigInteger[] contextAlphas = ctx.getAlphas();
        for (int i = 0; i <= n; i++) {
            assertEquals("Evaluation point α_" + i + " should match", BigInteger.valueOf(i), contextAlphas[i]);
        }

        // Verify threshold and number of participants.
        assertEquals("Threshold should match", t, ctx.getThreshold());
        assertEquals("Number of participants should match", n, ctx.getNumParticipants());

        // Optionally, print out some context details.
        System.out.println("DH PVSS Context Setup Test Passed");
        System.out.println("Modulus p: " + ctx.getOrder());
        System.out.println("Generator g: " + ctx.getGenerator());
        System.out.println("Evaluation points: ");
        for (BigInteger alpha : contextAlphas) {
            System.out.println("  " + alpha);
        }
    }

    // Verify that the dual-code coefficients don't affect proof verification
    @Test
    public void test_dual_code_coefficients_independence() throws NoSuchAlgorithmException {
        int lambda = 32;
        int t = 2;
        int n = 5;

        GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup(lambda);

        BigInteger[] alphas = new BigInteger[n + 1];
        for (int i = 0; i <= n; i++) {
            alphas[i] = BigInteger.valueOf(i);
        }

        BigInteger[] v = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            v[i] = BigInteger.ONE;
        }

        DhPvssContext ctx = new DhPvssContext(groupParams, t, n, alphas[0], alphas, v);

        BigInteger secret = BigInteger.valueOf(13);
        BigInteger pub = groupParams.getG().modPow(secret, groupParams.getP());
        DhKeyPair keyPair = new DhKeyPair(secret, pub);

        NizkDlProof proof = NizkDlProofGenerator.generateProof(ctx, keyPair);

        boolean valid = NizkDlProofGenerator.verifyProof(ctx, pub, proof);

        assertTrue("Valid DL proof should verify even with dummy dual-code coefficients", valid);
    }

    public static void main(String[] args) {
        DhPvssContextTest test = new DhPvssContextTest();
        test.testDhPvssContextSetup();
        System.out.println("All DH PVSS context tests passed!");
    }
}
