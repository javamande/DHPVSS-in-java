package org.example.pvss;

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;

public class GShamirShareDKGTest {
    private SecureRandom rnd = new SecureRandom();

    @Test
    public void testReconstructSecretEC() {

        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(GroupGenerator.generateGroup(), 5, 10);
        // 2) pick a random secret s mod p
        BigInteger s = new BigInteger(ctx.getOrder().bitLength(), rnd)
                .mod(ctx.getOrder());

        // generate all shares
        Share[] shares = GShamirShareDKG.generateShares(ctx, s);

        // threshold = 5 ⇒ need 6 shares
        int[] indices = new int[] { 1, 2, 3, 4, 5, 6 };

        Share[] subset = new Share[indices.length];
        for (int k = 0; k < indices.length; k++) {
            subset[k] = shares[indices[k] - 1];
        }

        // reconstruct S = s·G
        ECPoint Srec = GShamirShareDKG.reconstructSecretEC(ctx, subset, indices);

        // expected = G * s
        ECPoint expected = ctx.getGenerator().multiply(s).normalize();

        assertEquals("recovered ECPoint must match G·s", expected, Srec);
    }

    @Test
    public void testReconstructScalarAndEC() {

        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(GroupGenerator.generateGroup(), 5, 10);

        System.out.println("n=" + ctx.getNumParticipants()
                + "   t=" + ctx.getThreshold()
                + "   p=" + ctx.getOrder().toString(16));
        System.out.println("alphas: ");
        for (int i = 0; i < ctx.getAlphas().length; i++) {
            System.out.printf("  α[%d] = %s%n", i, ctx.getAlphas()[i].toString(16));
        }
        System.out.println("G = " + ctx.getGenerator());

        // pick random secret
        BigInteger s = new BigInteger(ctx.getOrder().bitLength(), rnd)
                .mod(ctx.getOrder());

        Share[] all = GShamirShareDKG.generateShares(ctx, s);

        for (int i = 1; i <= all.length; i++) {
            BigInteger ai = all[i - 1].getai();
            ECPoint Ai = all[i - 1].getAi();
            ECPoint check = ctx.getGenerator().multiply(ai).normalize();
            System.out.printf(
                    "share %2d: α=%s   aᵢ=%s%n         Aᵢ=%s%n check= %s  → %b%n",
                    i,
                    ctx.getAlphas()[i].toString(16),
                    ai.toString(16),
                    Ai,
                    check,
                    Ai.equals(check));
        }

        // threshold = 5 ⇒ need 6 shares
        int[] indices = new int[] { 1, 2, 3, 4, 5, 6 };

        Share[] subset = new Share[indices.length];
        for (int k = 0; k < indices.length; k++) {
            subset[k] = all[indices[k] - 1];
        }

        // 1) scalar
        BigInteger sRec = GShamirShareDKG.reconstructSecretScalar(ctx, subset, indices);
        System.out.println("scalar in is : " + s);
        System.out.println("scalar out is: " + sRec);
        assertEquals("scalar recovered must equal original", s, sRec);

        // 2) EC‐point
        ECPoint Srec = GShamirShareDKG.reconstructSecretEC(ctx, subset, indices);
        ECPoint expected = ctx.getGenerator().multiply(s).normalize();
        assertEquals("EC‐share must equal G·s", expected, Srec);
    }

    public static void main(String[] args) {
        GShamirShareDKGTest test = new GShamirShareDKGTest();
        test.testReconstructScalarAndEC();

    }

}
