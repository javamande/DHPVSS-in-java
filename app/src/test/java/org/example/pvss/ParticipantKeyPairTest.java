package org.example.pvss;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;

public class ParticipantKeyPairTest {

    @Test
    public void testGenerateForParticipant() throws NoSuchAlgorithmException {
        // Use a small lambda for testing (insecure but fast)

        GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup();
        int t = 1;
        int n = 3;
        BigInteger[] alphas = new BigInteger[n + 1];
        for (int i = 0; i <= n; i++) {
            alphas[i] = BigInteger.valueOf(i);
        }
        // Dummy dual-code coefficients:
        BigInteger[] v = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            v[i] = BigInteger.ONE;
        }

        DhPvssContext ctx = new DhPvssContext(groupParams, t, n, alphas, v);
        String participantId = "participant1";
        // Now call generateForParticipant with the context.
        ParticipantKeyPair participantKeyPair = DhKeyPairUtils.generateForParticipant(ctx, participantId);

        // Verify that the participant ID is set correctly.
        assertEquals("Participant ID should match", participantId, participantKeyPair.getId());

        // Retrieve the generated key pair.
        DhKeyPair keyPair = participantKeyPair.getKeyPair();
        ECPoint g = ctx.getGenerator();

        // Verify that the public key equals g^x mod p.
        // Verify that the participant ID is set correctly.
        assertEquals("Participant ID should match", participantId, participantKeyPair.getId());

        // Verify that the public key equals g^x mod p.
        ECPoint expectedPub = g.multiply(keyPair.getSecretKey());
        assertEquals("Public key verification for participant", expectedPub, keyPair.getPublic());

        // Generate the DLEQ proof that shows that the same x satisfies:
        // keyPair.getPublic() = g^x mod p and y = h^x mod p.
        NizkDlProof proof = NizkDlProofGenerator.generateProof(ctx, keyPair);

        ECPoint pub = keyPair.getPublic();
        // Verify the DLEQ proof.
        boolean proofValid = NizkDLProofVerificator.verifyProof(ctx, pub, proof);
        assertTrue("DL proof for participant should be valid", proofValid);
    }

    // Check that the PVSS context is properly initialized with the given parameters
    @Test
    public void test_pvss_context_initialization() throws NoSuchAlgorithmException {

        int t = 2;
        int n = 5;

        GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup();
        BigInteger[] alphas = new BigInteger[n + 1];
        for (int i = 0; i <= n; i++) {
            alphas[i] = BigInteger.valueOf(i);
        }
        BigInteger[] v = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            v[i] = BigInteger.ONE;
        }

        DhPvssContext ctx = new DhPvssContext(groupParams, t, n, alphas, v);

        assertTrue("PVSS context should be initialized with correct parameters",
                ctx != null && ctx.getThreshold() == t && ctx.getNumParticipants() == n);
    }

    // Confirm that key pair generation works correctly with a known secret value
    @Test
    public void test_key_pair_generation_with_known_secret() throws NoSuchAlgorithmException {
        GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup();

        BigInteger secretkey = BigInteger.valueOf(13);
        ECPoint pub = groupParams.getG().multiply(secretkey);
        DhKeyPair keyPair = new DhKeyPair(secretkey, pub);

        assertTrue("Key pair should be generated correctly with known secret",
                keyPair.getSecretKey().equals(secretkey) && keyPair.getPublic().equals(pub));
    }

    // A main method for quick standalone testing.
    public static void main(String[] args) throws NoSuchAlgorithmException {
        ParticipantKeyPairTest test = new ParticipantKeyPairTest();
        test.testGenerateForParticipant();
        test.test_pvss_context_initialization();
        System.out.println("Participant key pair test passed!");
    }
}
