package org.example.pvss;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.junit.Test;

public class DhPvssDistributionTest {

    @Test
    public void testDistribution() throws NoSuchAlgorithmException {
        int lambda = 32; // security parameter (small for testing)
        int t = 50; // threshold
        int n = 53; // number of participants

        // Generate finite-field group parameters.
        GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup(lambda);
        BigInteger p = groupParams.getP();

        // Create evaluation points α₀, α₁, …, αₙ.
        BigInteger[] alphas = new BigInteger[n + 1];
        for (int i = 0; i <= n; i++) {
            alphas[i] = BigInteger.valueOf(i);
        }

        // For this test, dual-code coefficients can be dummy values (set to 1).
        BigInteger[] v = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            v[i] = BigInteger.ONE;
        }
        DhPvssContext ctx = new DhPvssContext(groupParams, t, n, alphas[0], alphas, v);

        // Generate dummy commitment keys for each participant.
        // For testing, generate random elements in Z_p*.
        BigInteger[] comKeys = new BigInteger[n];
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < n; i++) {
            BigInteger key;
            do {
                key = new BigInteger(p.bitLength(), random);
            } while (key.compareTo(BigInteger.ZERO) <= 0 || key.compareTo(p) >= 0);
            comKeys[i] = key;
        }
        // Create the dealer's key pair.
        // For finite-field groups, secret key is an element in [1, q-1],
        // and public key is g^(secret) mod p.
        BigInteger secretDealer = BigInteger.valueOf(13);
        BigInteger pubDealer = groupParams.getG().modPow(secretDealer, p);
        DhKeyPair dealerKeyPair = new DhKeyPair(secretDealer, pubDealer);

        // Define the secret S to be shared (an element in G).
        // For simplicity, let S be a small number.
        BigInteger secret = BigInteger.valueOf(17);

        // Call the distribution function.
        DHPVSSDistribution.DistributionResult result = DHPVSSDistribution.dhPvssDistributeProve(ctx, comKeys,
                dealerKeyPair, secret);

        // Assert that we have non-null encrypted shares and a DLEQ proof.
        assertNotNull("Distribution result should not be null", result);
        assertNotNull("Encrypted shares should not be null", result.getEncryptedShares());
        assertNotNull("DLEQ proof should not be null", result.getProof());

        // Print the distribution result for debugging.
        System.out.println("Distribution Result:");
        System.out.println(result);
    }

    /**
     * Test that the Shamir secret sharing shares can be generated and that the
     * secret can be reconstructed.
     */
    @Test
    public void testShamirShareGeneration() {
        int lambda = 32; // security parameter (small for testing)
        int t = 40; // threshold (we need t+1 shares to reconstruct)
        int n = 45; // number of participants

        GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup(lambda);
        BigInteger p = groupParams.getP();
        BigInteger G = groupParams.getG();

        // Create evaluation points: α₀, α₁, …, αₙ.
        BigInteger[] alphas = new BigInteger[n + 1];
        for (int i = 0; i <= n; i++) {
            alphas[i] = BigInteger.valueOf(i);
        }
        // Dummy dual-code coefficients.
        BigInteger[] v = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            v[i] = BigInteger.ONE;
        }
        DhPvssContext ctx = new DhPvssContext(groupParams, t, n, alphas[0], alphas, v);

        // Let the secret S be 7.
        BigInteger secret = BigInteger.valueOf(7);
        // Generate shares using SSS.generateShares (assumed to follow YOLO YOSO, e.g.
        // with m(X)=2X).
        BigInteger[] shares = SSSStandard.generateSharesStandard(ctx, secret);
        assertNotNull("Shares should not be null", shares);
        assertEquals("Number of shares should equal n", n, shares.length);

        // For reconstruction, we need t+1 shares.
        int tPlusOne = t + 1;
        int[] indices = new int[tPlusOne];
        BigInteger[] recShares = new BigInteger[tPlusOne];
        for (int i = 0; i < tPlusOne; i++) {
            indices[i] = i + 1; // evaluation points for participants 1...t+1.
            recShares[i] = shares[i]; // shares are stored starting at index 0 corresponding to participant 1.
        }

        BigInteger reconstructed = SSSStandard.reconstructSecretStandard(ctx, recShares, indices);
        assertEquals("Reconstructed secret should equal original secret", secret, reconstructed);
    }

    /**
     * Test that the share encryption is performed correctly.
     */
    @Test
    public void testShareEncryption() {
        int lambda = 32;
        int t = 1;
        int n = 3;
        GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup(lambda);
        BigInteger p = groupParams.getP();
        BigInteger[] alphas = new BigInteger[n + 1];
        for (int i = 0; i <= n; i++) {
            alphas[i] = BigInteger.valueOf(i);
        }
        BigInteger[] v = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            v[i] = BigInteger.ONE;
        }
        DhPvssContext ctx = new DhPvssContext(groupParams, t, n, alphas[0], alphas, v);

        // Let secret S be 7 and generate shares.
        BigInteger secret = BigInteger.valueOf(7);
        BigInteger[] shares = SSSStandard.generateSharesStandard(ctx, secret);

        // Generate dummy commitment keys for each participant.
        BigInteger[] comKeys = new BigInteger[n];
        SecureRandom rnd = new SecureRandom();
        for (int i = 0; i < n; i++) {
            BigInteger key;
            do {
                key = new BigInteger(p.bitLength(), rnd);
            } while (key.compareTo(BigInteger.ZERO) <= 0 || key.compareTo(p) >= 0);
            comKeys[i] = key;
        }

        // Create a dealer's key pair.
        BigInteger dealerSecret = BigInteger.valueOf(11);
        BigInteger dealerPub = groupParams.getG().modPow(dealerSecret, p);
        DhKeyPair dealerKey = new DhKeyPair(dealerSecret, dealerPub);

        // Manually compute the expected encryption for the first share:
        // encryptedShare[0] = comKeys[0] * dealerSecret + shares[0] mod p.
        BigInteger expected = comKeys[0].multiply(dealerSecret).mod(p).add(shares[0]).mod(p);
        BigInteger actual = comKeys[0].multiply(dealerKey.getSecretKey()).mod(p)
                .add(shares[0]).mod(p);
        assertEquals("Encrypted share should be computed correctly", expected, actual);
    }

    /**
     * Test the complete distribution process: generating shares, encrypting them,
     * and producing a DLEQ proof.
     */
    @Test
    public void testDistributionComplete() throws NoSuchAlgorithmException {
        int lambda = 32;
        int t = 2;
        int n = 5;
        GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup(lambda);
        BigInteger p = groupParams.getP();
        BigInteger[] alphas = new BigInteger[n + 1];
        for (int i = 0; i <= n; i++) {
            alphas[i] = BigInteger.valueOf(i);
        }
        BigInteger[] v = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            v[i] = BigInteger.ONE;
        }
        DhPvssContext ctx = new DhPvssContext(groupParams, t, n, alphas[0], alphas, v);

        // Generate dummy commitment keys.
        BigInteger[] comKeys = new BigInteger[n];
        SecureRandom rnd = new SecureRandom();
        for (int i = 0; i < n; i++) {
            BigInteger key;
            do {
                key = new BigInteger(p.bitLength(), rnd);
            } while (key.compareTo(BigInteger.ZERO) <= 0 || key.compareTo(p) >= 0);
            comKeys[i] = key;
        }

        // Create the dealer's key pair.
        BigInteger dealerSecret = BigInteger.valueOf(13);
        BigInteger dealerPub = groupParams.getG().modPow(dealerSecret, p);
        DhKeyPair dealerKey = new DhKeyPair(dealerSecret, dealerPub);

        // Define the secret S to be shared.
        BigInteger secret = BigInteger.valueOf(17);

        // Perform the distribution.
        DHPVSSDistribution.DistributionResult result = DHPVSSDistribution.dhPvssDistributeProve(ctx, comKeys, dealerKey,
                secret);

        // Basic checks: non-null result, shares, and a DLEQ proof.
        assertNotNull("Distribution result should not be null", result);
        assertNotNull("Encrypted shares should not be null", result.getEncryptedShares());
        assertNotNull("DLEQ proof should not be null", result.getProof());

        // Optionally, print out the distribution result for inspection.
        System.out.println("Distribution result:");
        System.out.println(result);
    }

    public static void main(String[] args) throws Exception {
        DhPvssDistributionTest test = new DhPvssDistributionTest();
        test.testDistribution();
        test.testShamirShareGeneration();
        test.testShareEncryption();
        test.testDistributionComplete();
        System.out.println("DHPVSS distribution test passed!");
    }
}
