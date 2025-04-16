package org.example.pvss;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;


import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;

/**
 * Unit tests for the DHPVSS_Verify public verification routine.
 */
public class DhPvssVerifyTest {

    /**
     * A full valid distribution should verify successfully.
     */

    @Test
    public void testVerifyValidDistribution() throws Exception {
        int t = 2, n = 5;
        GroupGenerator.GroupParameters gp = GroupGenerator.generateGroup();
        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(gp, t, n);

        // Dealer keypair + secret S
        DhKeyPair dealer = DhKeyPair.generate(ctx);
        BigInteger s = dealer.getSecretKey().mod(ctx.getOrder());
        ECPoint S = ctx.getGenerator().multiply(s);

        // Build wrappers
        EphemeralKeyPublic[] epks = new EphemeralKeyPublic[n];
        for (int i = 0; i < n; i++) {
            DhKeyPair kp = DhKeyPair.generate(ctx);
            NizkDlProof proof = NizkDlProof.generateProof(ctx, kp);
            epks[i] = new EphemeralKeyPublic(kp.getPublic(), proof);
        }

        // Distribute
        DHPVSS_Dist.DistributionResult dr = DHPVSS_Dist.distribute(ctx, epks, dealer, S);
        ECPoint[] C = dr.getEncryptedShares();
        NizkDlEqProof dleq = dr.getDleqProof();

        // Extract raw ephemeral points
        ECPoint[] E = new ECPoint[n];
        for (int i = 0; i < n; i++) {
            E[i] = epks[i].getPublicKey();
        }

        // Verify
        boolean ok = DHPVSS_Verify.verify(ctx, dealer.getPublic(), E, C, dleq);
        assertTrue("Valid distribution must verify", ok);
    }

    /**
     * Tampering with one encrypted share must cause verification to fail.
     */
    @Test
    public void testVerifyFailsOnTamperedShare() throws Exception {
        int t = 2, n = 5;

        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(
                GroupGenerator.generateGroup(), t, n);
        DhKeyPair dealer = DhKeyPair.generate(ctx);
        ECPoint S = ctx.getGenerator().multiply(dealer.getSecretKey().mod(ctx.getOrder()));

        EphemeralKeyPublic[] epks = new EphemeralKeyPublic[n];
        for (int i = 0; i < n; i++) {
            DhKeyPair kp = DhKeyPair.generate(ctx);
            NizkDlProof proof = NizkDlProof.generateProof(ctx, kp);
            epks[i] = new EphemeralKeyPublic(kp.getPublic(), proof);
        }
        DHPVSS_Dist.DistributionResult dr = DHPVSS_Dist.distribute(ctx, epks, dealer, S);
        ECPoint[] C = dr.getEncryptedShares();
        NizkDlEqProof dleq = dr.getDleqProof();

        // Extract ephemeral
        ECPoint[] E = new ECPoint[n];
        for (int i = 0; i < n; i++) {
            E[i] = epks[i].getPublicKey();
        }

        // Tamper
        C[2] = C[2].add(ctx.getGenerator());

        boolean ok = DHPVSS_Verify.verify(ctx, dealer.getPublic(), E, C, dleq);
        assertFalse("Tampered share must fail verification", ok);
    }

    /**
     * Mismatched array lengths should throw IllegalArgumentException.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testVerifyWrongLengths() {
        int t = 2, n = 5;

        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(
                GroupGenerator.generateGroup(), t, n);
        // Dummy inputs of wrong length
        ECPoint[] E = new ECPoint[n - 1];
        ECPoint[] C = new ECPoint[n];
        NizkDlEqProof dummyProof = null;
        // Should throw IllegalArgumentException
        DHPVSS_Verify.verify(ctx, null, E, C, dummyProof);
    }
}
