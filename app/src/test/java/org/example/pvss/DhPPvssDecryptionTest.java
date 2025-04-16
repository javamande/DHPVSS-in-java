package org.example.pvss;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.Before;
import org.junit.Test;

public class DhPPvssDecryptionTest {

    private DhPvssContext ctx;
    private int t = 2, n = 5;

    // We’ll need both the ephemeral public wrappers *and* their secrets
    private DhKeyPair[] ephKeyPairs;
    private EphemeralKeyPublic[] epkWrapped;
    private ECPoint[] encryptedShares;
    private ECPoint dealerPublic;
    private DhKeyPair dealerKP;

    @Before
    public void setUp() throws Exception {
        GroupGenerator.GroupParameters gp = GroupGenerator.generateGroup();
        ctx = DHPVSS_Setup.dhPvssSetup(gp, t, n);

        // 1) Prepare dealer + secret
        dealerKP = DhKeyPair.generate(ctx);
        dealerPublic = dealerKP.getPublic();
        BigInteger s = dealerKP.getSecretKey().mod(ctx.getOrder());
        ECPoint S = ctx.getGenerator().multiply(s);

        // 2) Build ephemeral key–pairs and wrappers
        ephKeyPairs = new DhKeyPair[n];
        epkWrapped = new EphemeralKeyPublic[n];
        for (int i = 0; i < n; i++) {
            ephKeyPairs[i] = DhKeyPair.generate(ctx);
            NizkDlProof p = NizkDlProof.generateProof(ctx, ephKeyPairs[i]);
            epkWrapped[i] = new EphemeralKeyPublic(ephKeyPairs[i].getPublic(), p);
        }

        // 3) Distribute
        DHPVSS_Dist.DistributionResult dr = DHPVSS_Dist.distribute(ctx, epkWrapped, dealerKP, S);
        encryptedShares = dr.getEncryptedShares();
    }

    @Test
    public void testDecSharePerIndex() throws Exception {
        // For each i, decrypt and verify the share + proof
        for (int i = 0; i < n; i++) {
            ECPoint E_i = ephKeyPairs[i].getPublic();
            BigInteger skE = ephKeyPairs[i].getSecretKey();
            ECPoint C_i = encryptedShares[i];

            // recompute the mask that you proved knowledge of:
            ECPoint delta = dealerPublic.multiply(skE).normalize();

            DhPvss_Decryption.DecryptionShare ds = DhPvss_Decryption.decShare(ctx, dealerPublic, E_i, skE, C_i);

            // 1) sanity check: A_i = C_i - delta
            assertEquals(
                    "Recovered share must be C_i - delta",
                    C_i.subtract(delta).normalize(),
                    ds.getShare());

            // 2) verify the proof on (E_i, delta)
            assertTrue(
                    "Per‐share proof must verify for index=" + i,
                    NizkDlEqProof.verifyProof(
                            ctx, // base1 = G
                            dealerPublic, // base2 = pk_D
                            E_i, // h1 = E_i = G^skE
                            delta, // h2 = delta = pkD^skE
                            ds.getProof()));
        }
    }

}
