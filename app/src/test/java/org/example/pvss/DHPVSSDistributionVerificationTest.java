package org.example.pvss;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.junit.Test;

public class DHPVSSDistributionVerificationTest {
    @Test
    public void testDistributionVerification() throws NoSuchAlgorithmException {
        int lambda = 10; // 128-bit security parameter for a larger prime
        int t = 2; // threshold
        int n = 5; // number of participants

        DhPvssContext ctx = createContext(lambda, t, n);
        BigInteger p = ctx.getOrder();
        SecureRandom rnd = new SecureRandom();

        // Generate dummy commitment keys.
        BigInteger[] comKeys = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            BigInteger key;
            do {
                key = new BigInteger(p.bitLength(), rnd);
            } while (key.compareTo(BigInteger.ZERO) == 0 || key.compareTo(p) >= 0);
            comKeys[i] = key;
        }

        // Create dealer's key pair.
        BigInteger dealerSecret = BigInteger.valueOf(13);
        BigInteger dealerPub = ctx.getGenerator().modPow(dealerSecret, p);
        DhKeyPair dealerKey = new DhKeyPair(dealerSecret, dealerPub);

        // Define the secret S to be shared.
        BigInteger secret = BigInteger.valueOf(17);

        // Perform distribution.
        DHPVSSDistribution.DistributionResult result = DHPVSSDistribution.dhPvssDistributeProve(ctx, comKeys, dealerKey,
                secret);
        assertNotNull("Distribution result should not be null", result);
        assertNotNull("Encrypted shares should not be null", result.getEncryptedShares());
        assertNotNull("DLEQ proof should not be null", result.getProof());

        // Now, verify the distribution.
        boolean valid = DHPVSSDistributionVerifier.dhPvssDistributeVerify(ctx, result.getProof(),
                result.getEncryptedShares(), dealerPub, comKeys);
        assertTrue("Distribution verification should pass", valid);
    }

    /**
     * Helper method to create a DhPvssContext with given parameters.
     */
    private DhPvssContext createContext(int lambda, int t, int n) {
        GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup(lambda);
        BigInteger[] alphas = new BigInteger[n + 1];
        for (int i = 0; i <= n; i++) {
            alphas[i] = BigInteger.valueOf(i);
        }
        BigInteger[] v = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            v[i] = BigInteger.ONE;
        }
        return new DhPvssContext(groupParams, t, n, alphas[0], alphas, v);
    }

    /**
     * Test distribution verification with larger parameters.
     */
    @Test
    public void testDistributionLargeParameters() throws NoSuchAlgorithmException {
        int lambda = 128; // 128-bit security parameter for a larger prime
        int t = 50; // threshold (requires t+1 shares for reconstruction)
        int n = 200; // total number of participants

        // Create PVSS context.
        DhPvssContext ctx = createContext(lambda, t, n);
        BigInteger p = ctx.getOrder();
        SecureRandom rnd = new SecureRandom();
        System.out.println("PVSS Context:");
        System.out.println("  p: " + p);
        System.out.println("  g: " + ctx.getGenerator());
        System.out.println("  t: " + t + ", n: " + n);

        // Generate dummy commitment keys for each participant.
        BigInteger[] comKeys = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            BigInteger key;
            do {
                key = new BigInteger(p.bitLength(), rnd);
            } while (key.compareTo(BigInteger.ZERO) == 0 || key.compareTo(p) >= 0);
            comKeys[i] = key;
        }
        System.out.println("Generated commitment keys for " + n + " participants.");

        // Create dealer's key pair.
        BigInteger dealerSecret = new BigInteger(p.bitLength() - 1, rnd)
                .mod(ctx.getGroupParameters().getSubgroupOrder());
        BigInteger dealerPub = ctx.getGenerator().modPow(dealerSecret, p);
        DhKeyPair dealerKey = new DhKeyPair(dealerSecret, dealerPub);
        System.out.println("Dealer's key pair: secret=" + dealerSecret + ", public=" + dealerPub);

        // Define a random secret S in Z_p.
        BigInteger secret = new BigInteger(p.bitLength() - 1, rnd).mod(p);
        System.out.println("Secret to share: " + secret);

        // Perform the distribution.
        DHPVSSDistribution.DistributionResult result = DHPVSSDistribution.dhPvssDistributeProve(ctx, comKeys, dealerKey,
                secret);
        assertNotNull("Distribution result should not be null", result);
        assertNotNull("Encrypted shares should not be null", result.getEncryptedShares());
        assertNotNull("DLEQ proof should not be null", result.getProof());
        System.out.println("Distribution result:");
        System.out.println(result);

        // Verify the distribution.
        boolean valid = DHPVSSDistributionVerifier.dhPvssDistributeVerify(ctx, result.getProof(),
                result.getEncryptedShares(), dealerPub, comKeys);
        assertTrue("Distribution verification should pass", valid);
        System.out.println("Distribution verification passed.");
    }

    public static void main(String[] args) throws Exception {
        DHPVSSDistributionVerificationTest test = new DHPVSSDistributionVerificationTest();
        test.testDistributionVerification();
        // test.testDistributionLargeParameters();
        System.out.println("DHPVSS distribution verification test passed!");
    }
}
