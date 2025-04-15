package org.example.pvss;

import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;

public class NizkDlEqProofTest {

    @Test
    public void testDleqProofGenerationAndVerification() throws Exception {
        // Setup the elliptic curve group using secp256r1.

        int maxPartipants = 100;
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

                    GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup();

                    DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(groupParams, t, n);

                    SecureRandom random = new SecureRandom();
                    DistributionInput distInput = DistributionInputGenerator.generateDistributionInput(ctx, random);
                    DhKeyPair keypair = distInput.getDealerKeyPair();
                    BigInteger skD = keypair.getSecretKey();
                    // Generate a dealer secret sk_D
                    // BigInteger skD;
                    // do {
                    // skD = new BigInteger(groupParams.getN().bitLength(), random);
                    // } while (skD.compareTo(BigInteger.ZERO) <= 0);
                    // Dealer's public key: pk_D = [skD]G
                    ECPoint G = ctx.getGenerator();
                    ECPoint pkD = keypair.getPublic();
                    ECPoint S = distInput.getSecret();
                    // Retrieve the list of participant key pairs.
                    EphemeralKeyPublic[] participantKeyPairs = distInput.getEphemeralKeys();

                    // Build an array of ECPoints to be used as the commitment keys.
                    ECPoint[] comKeys = new ECPoint[participantKeyPairs.length];
                    for (int k = 0; k < participantKeyPairs.length; k++) {
                        // For instance, if you want to use each participant’s public key as their
                        // commitment key:
                        comKeys[k] = participantKeyPairs[i].getPublicKey();
                    }

                    ECPoint[] encryptedShares = GShamir_Share.generateSharesEC(ctx, S);

                    BigInteger modulus = ctx.getOrder();

                    BigInteger[] polyCoeffs = ctx.getAlphas();
                    int numPolyCoeffs = polyCoeffs.length;

                    polyCoeffs = HashingTools.hashPointsToPoly(pkD, comKeys, encryptedShares,
                            numPolyCoeffs,
                            modulus);

                    // Now choose a random scalar u to compute a secondary base U = [u]G.
                    BigInteger u;
                    do {
                        u = new BigInteger(groupParams.getN().bitLength(), random);
                    } while (u.compareTo(BigInteger.ZERO) <= 0);

                    ECPoint U = G.multiply(u).normalize();
                    // Compute V = [skD]U.
                    ECPoint V = U.multiply(skD).normalize();

                    // Generate the DLEQ proof that proves the relation:
                    // pk_D = [skD]G and V = [skD]U.
                    NizkDlEqProof proof = NizkDlEqProof.generateProof(ctx, U, pkD, V, skD);
                    // Verify the proof.
                    boolean valid = NizkDlEqProof.verifyProof(ctx, U, pkD, V, proof);
                    System.out.println("DLEQ proof valid: " + valid + " " + i + " of 10 completed tests");
                    assertTrue("DLEQ proof should verify", valid);

                }
            }
        }
    }

    public static void main(String[] args) throws Exception {
        NizkDlEqProofTest test = new NizkDlEqProofTest();
        test.testDleqProofGenerationAndVerification();
        System.out.println("Participant DLEQ test passed!");
    }
}
