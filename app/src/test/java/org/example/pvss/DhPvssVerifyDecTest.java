package org.example.pvss;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.Before;
import org.junit.Test;

/**
 * Unit tests for DHPVSS_VerifyDec: verifying decryption shares.
 */
public class DhPvssVerifyDecTest {
    private DhPvssContext ctx;
    private int t = 2, n = 5;

    private DhKeyPair dealerKP;
    private ECPoint dealerPublic;
    private ECPoint S;

    private DhKeyPair[] ephKeyPairs;
    private EphemeralKeyPublic[] epkWrapped;
    private ECPoint[] encryptedShares;

    @Before
    public void setUp() throws Exception {

        GroupGenerator.GroupParameters gp = GroupGenerator.generateGroup();
        ctx = DHPVSS_Setup.dhPvssSetup(gp, t, n);

        // Dealer keypair + secret S = G·s
        dealerKP = DhKeyPair.generate(ctx);
        dealerPublic = dealerKP.getPublic();
        BigInteger s = dealerKP.getSecretKey().mod(ctx.getOrder());
        S = ctx.getGenerator().multiply(s);

        // Build ephemeral key–pairs and proof wrappers
        ephKeyPairs = new DhKeyPair[n];
        epkWrapped = new EphemeralKeyPublic[n];
        for (int i = 0; i < n; i++) {
            ephKeyPairs[i] = DhKeyPair.generate(ctx);
            NizkDlProof p = NizkDlProof.generateProof(ctx, ephKeyPairs[i]);
            epkWrapped[i] = new EphemeralKeyPublic(ephKeyPairs[i].getPublic(), p);
        }

        // Distribute to get encrypted shares
        DHPVSS_Dist.DistributionResult dr = DHPVSS_Dist.distribute(ctx, epkWrapped, dealerKP, S);
        encryptedShares = dr.getEncryptedShares();
    }

    @Test
    public void testVerifyDecOnValidShare() throws Exception {
        // For each participant index, decrypt and verify
        for (int i = 0; i < n; i++) {
            ECPoint E_i = ephKeyPairs[i].getPublic();
            BigInteger skE = ephKeyPairs[i].getSecretKey();
            ECPoint C_i = encryptedShares[i];

            // Recover share & proof
            DhPvss_Decryption.DecryptionShare ds = DhPvss_Decryption.decShare(ctx, dealerPublic, E_i, skE, C_i);
            ECPoint A_i = ds.getShare();
            NizkDlEqProof proof = ds.getProof();

            // 1) A_i must equal C_i - skE*pkD
            ECPoint delta = dealerPublic.multiply(skE).normalize();
            ECPoint expectedShare = C_i.subtract(delta).normalize();
            assertEquals("Recovered share mismatch at index " + i,
                    expectedShare, A_i);

            // 2) verifyDec should return true
            assertTrue("verifyDec must pass for index=" + i,
                    DhPvss_VerifyDec.verifyDec(
                            ctx, dealerPublic, E_i, C_i, A_i, proof));
        }
    }

    @Test
    public void testVerifyDecFailsOnTamperedCi() throws Exception {
        // Take one index and tamper its C_i
        int i = 2;
        ECPoint E_i = ephKeyPairs[i].getPublic();
        BigInteger skE = ephKeyPairs[i].getSecretKey();
        ECPoint C_i = encryptedShares[i];

        DhPvss_Decryption.DecryptionShare ds = DhPvss_Decryption.decShare(ctx, dealerPublic, E_i, skE, C_i);
        ECPoint A_i = ds.getShare();
        NizkDlEqProof proof = ds.getProof();

        // Tamper C_i
        ECPoint C_bad = C_i.add(ctx.getGenerator()).normalize();

        assertFalse("verifyDec must fail on tampered C_i",
                DhPvss_VerifyDec.verifyDec(
                        ctx, dealerPublic, E_i, C_bad, A_i, proof));
    }

    @Test
    public void testVerifyDecFailsOnTamperedAi() throws Exception {
        // Take one index and tamper its A_i
        int i = 3;
        ECPoint E_i = ephKeyPairs[i].getPublic();
        BigInteger skE = ephKeyPairs[i].getSecretKey();
        ECPoint C_i = encryptedShares[i];

        DhPvss_Decryption.DecryptionShare ds = DhPvss_Decryption.decShare(ctx, dealerPublic, E_i, skE, C_i);
        ECPoint A_i = ds.getShare();
        NizkDlEqProof proof = ds.getProof();

        // Tamper A_i
        ECPoint A_bad = A_i.add(ctx.getGenerator()).normalize();

        assertFalse("verifyDec must fail on tampered A_i",
                DhPvss_VerifyDec.verifyDec(
                        ctx, dealerPublic, E_i, C_i, A_bad, proof));
    }
}