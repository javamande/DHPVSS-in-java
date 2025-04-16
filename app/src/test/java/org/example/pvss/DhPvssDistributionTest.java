package org.example.pvss;

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;

public class DhPvssDistributionTest {

    /**
     * End‐to‐end: distribute → decrypt → reconstruct → must get back S
     * 
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void testDistributeDecryptsAndReconstructs() throws NoSuchAlgorithmException {
        int t = 2, n = 5;
        GroupGenerator.GroupParameters gp = GroupGenerator.generateGroup();
        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(gp, t, n);

        // Dealer key‐pair + secret point S = G·s
        DhKeyPair dealer = DhKeyPair.generate(ctx);
        BigInteger s = dealer.getSecretKey().mod(ctx.getOrder());
        ECPoint S = ctx.getGenerator().multiply(s);

        EphemeralKeyPublic[] epks = new EphemeralKeyPublic[n];
        for (int i = 0; i < n; i++) {
            DhKeyPair kp = DhKeyPair.generate(ctx);
            // generate a DL proof for the ephemeral key
            NizkDlProof proof = NizkDlProof.generateProof(ctx, kp);
            epks[i] = new EphemeralKeyPublic(kp.getPublic(), proof);
        }

        // Run distribution
        DHPVSS_Dist.DistributionResult dr = DHPVSS_Dist.distribute(ctx, epks, dealer, S);
        ECPoint[] C = dr.getEncryptedShares();

        // Decrypt shares: A' = C - sk_D·E
        ECPoint[] Aprime = new ECPoint[n];
        BigInteger skD = dealer.getSecretKey();
        for (int i = 0; i < n; i++) {
            ECPoint mask = epks[i].getPublicKey().multiply(skD).normalize();
            Aprime[i] = C[i].subtract(mask).normalize();
        }

        // Reconstruct S using any t+1 shares (here, the first three)
        int k = t + 1;
        ECPoint[] subset = new ECPoint[k];
        int[] indices = new int[k];
        for (int i = 0; i < k; i++) {
            subset[i] = Aprime[i];
            indices[i] = i + 1;
        }
        ECPoint recovered = GShamir_Share.reconstructSecretEC(ctx, subset, indices);

        assertEquals("Reconstruction must yield original S", S, recovered);
    }

    /**
     * Passing a too‐short ephemeral-key array (but fully populated) should throw
     * an IndexOutOfBoundsException.
     * 
     * @throws NoSuchAlgorithmException
     */
    @Test(expected = IndexOutOfBoundsException.class)
    public void testDistributionWrongEphemeralLength() throws NoSuchAlgorithmException {

        int t = 2, n = 5;
        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(
                GroupGenerator.generateGroup(), t, n);
        DhKeyPair dealer = DhKeyPair.generate(ctx);
        ECPoint S = ctx.getGenerator().multiply(
                dealer.getSecretKey().mod(ctx.getOrder()));

        // Build a too‐short but fully‐populated array
        EphemeralKeyPublic[] epks = new EphemeralKeyPublic[n - 1];
        for (int i = 0; i < epks.length; i++) {
            DhKeyPair kp = DhKeyPair.generate(ctx);
            NizkDlProof proof = NizkDlProof.generateProof(ctx, kp);
            epks[i] = new EphemeralKeyPublic(kp.getPublic(), proof);
        }
        DHPVSS_Dist.distribute(ctx, epks, dealer, S);
    }
}
