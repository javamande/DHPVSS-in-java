package org.example.pvss;

import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import org.junit.Test;

public class DLProofTest {
    // Verify that a valid DL proof is correctly verified
    @Test
    public void test_valid_dl_proof_verification() throws NoSuchAlgorithmException {
        int lambda = 32; // Small parameter for testing.
        int t = 2; // threshold
        int n = 5; // number of participants

        // Generate finite-field group parameters.
        GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup(lambda);

        // Create evaluation points α₀, α₁, …, αₙ.
        BigInteger[] alphas = new BigInteger[n + 1];
        for (int i = 0; i <= n; i++) {
            alphas[i] = BigInteger.valueOf(i);
        }

        // For this DL proof test, dual-code coefficients can be dummy.
        BigInteger[] v = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            v[i] = BigInteger.ONE;
        }

        // Create the PVSS context.
        DhPvssContext ctx = new DhPvssContext(groupParams, t, n, alphas[0], alphas, v);

        // Choose a secret x = 13 and compute the public key: pub = g^x mod p.
        BigInteger secret = BigInteger.valueOf(13);
        BigInteger pub = groupParams.getG().modPow(secret, groupParams.getP());
        DhKeyPair keyPair = new DhKeyPair(secret, pub);

        // Generate the DL proof using the context.
        NizkDlProof proof = NizkDlProofGenerator.generateProof(ctx, keyPair);

        // Verify the DL proof.
        boolean valid = NizkDlProofGenerator.verifyProof(ctx, pub, proof);

        assertTrue("Valid DL proof should verify", valid);
    }

    // Test with different secret values other than 7
    @Test
    public void test_different_secret_values() throws NoSuchAlgorithmException {
        int lambda = 32; // Small parameter for testing.
        int t = 2; // threshold
        int n = 5; // number of participants

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

        BigInteger[] secrets = { BigInteger.valueOf(5), BigInteger.valueOf(13), BigInteger.valueOf(19) };
        for (BigInteger secret : secrets) {
            BigInteger pub = groupParams.getG().modPow(secret, groupParams.getP());
            DhKeyPair keyPair = new DhKeyPair(secret, pub);
            NizkDlProof proof = NizkDlProofGenerator.generateProof(ctx, keyPair);
            boolean valid = NizkDlProofGenerator.verifyProof(ctx, pub, proof);
            assertTrue("DL proof should verify for secret: " + secret, valid);
        }
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        DLProofTest test = new DLProofTest();
        test.test_valid_dl_proof_verification();
        test.test_different_secret_values();
    
        System.out.println("DL proof tests passed!");
    }
}
