package org.example.pvss;

import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import org.junit.Test;

public class DLEQProofTest {

    /**
     * This test generates a DLEQ proof using a fixed secret exponent α,
     * then verifies the proof. Debug output is printed during generation
     * and verification.
     */
    @Test
    public void testValidDleqProofVerification() throws NoSuchAlgorithmException {
        // Use a small lambda for testing.
        int lambda = 32;
        int t = 2; // threshold (not used in DLEQ, but required by context)
        int n = 5; // number of participants (not used in DLEQ, but required by context)

        // Generate finite-field group parameters.
        GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup(lambda);

        // Create evaluation points α₀, α₁, …, αₙ.
        BigInteger[] alphas = new BigInteger[n + 1];
        for (int i = 0; i <= n; i++) {
            alphas[i] = BigInteger.valueOf(i);
        }

        // Dummy dual-code coefficients for the context.
        BigInteger[] v = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            v[i] = BigInteger.ONE;
        }

        // Create the PVSS context.
        DhPvssContext ctx = new DhPvssContext(groupParams, t, n, alphas[0], alphas, v);

        // Set a fixed secret exponent α.
        BigInteger alpha = BigInteger.valueOf(7);
        // Compute x = g^α mod p.
        BigInteger x = groupParams.getG().modPow(alpha, groupParams.getP());

        // Choose a second base h. (Ensure h != 1)
        BigInteger h = BigInteger.valueOf(11).mod(groupParams.getP());
        // Compute y = h^α mod p.
        BigInteger y = h.modPow(alpha, groupParams.getP());

        // Generate a DLEQ proof that x = g^α and y = h^α.
        NizkDlEqProof proof = NizkDlEqProofGenerator.generateProof(ctx, h, x, y, alpha);

        // Verify the DLEQ proof.
        boolean valid = NizkDlEqProofGenerator.verifyProof(ctx, h, x, y, proof);
        assertTrue("DLEQ proof should be valid", valid);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        DLEQProofTest test = new DLEQProofTest();
        test.testValidDleqProofVerification();
        System.out.println("DLEQ proof test passed!");
    }
}
