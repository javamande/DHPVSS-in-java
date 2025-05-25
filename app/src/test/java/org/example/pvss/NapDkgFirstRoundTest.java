package org.example.pvss;

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Before;
import org.junit.Test;

public class NapDkgFirstRoundTest {
    private DhPvssContext ctx;
    private SecureRandom rnd;
    private int n, t;
    private DhKeyPair[] ephKeyPairs;
    private EphemeralKeyPublic[] epkWrapped;
    private BigInteger[] r; // each party’s dealer secret
    private InMemoryPbbClient pbb;

    @Before
    public void setUp() throws Exception {
        // 1) parameters
        n = 6;
        t = 3;
        rnd = new SecureRandom();

        ctx = DHPVSS_Setup.dhPvssSetup(GroupGenerator.generateGroup(), t, n);

        // 3) ephemeral keypairs + proofs
        ephKeyPairs = new DhKeyPair[n];
        epkWrapped = new EphemeralKeyPublic[n];
        for (int i = 0; i < n; i++) {
            DhKeyPair kp = DhKeyPair.generate(ctx);
            NizkDlProof proof = NizkDlProof.generateProof(ctx, kp);
            ephKeyPairs[i] = kp;
            epkWrapped[i] = new EphemeralKeyPublic(kp.getPublic(), proof);
        }
        // publish them (in‐memory PBB)
        pbb = new InMemoryPbbClient("http://localhost:3000");
        pbb.publishAll(epkWrapped);

        // 4) dealer secrets r[i]
        r = new BigInteger[n];
        BigInteger p = ctx.getOrder();
        for (int i = 0; i < n; i++) {
            r[i] = new BigInteger(p.bitLength(), rnd).mod(p);
        }
    }

    /**
     * Test the Shamir‐share generation and reconstruction for ONE dealer (say
     * dealer 1).
     */
    @Test
    public void testShamirShareReconstruction() {
        // --- BUG #1 was here: you were reassigning `shares` inside the loop ---
        // Instead, generate one array of n shares for dealer #1:
        Share[] shares = GShamirShareDKG.generateShares(ctx, r[1]);

        // pick the first t+1 = 4 shares to reconstruct
        int[] idx = new int[t + 1];
        for (int i = 0; i < idx.length; i++) {
            idx[i] = i + 1;
        }
        Share[] subset = new Share[idx.length];
        for (int i = 0; i < idx.length; i++) {
            subset[i] = shares[idx[i] - 1];
        }

        // 1) reconstruct the scalar s = m(α₀)
        BigInteger sRec = GShamirShareDKG.reconstructSecretScalar(ctx, subset, idx);
        assertEquals(
                "Reconstructed scalar must match dealer's secret",
                r[1], sRec);

        // 2) reconstruct the group element S = s·G
        ECPoint Srec = GShamirShareDKG.reconstructSecretEC(ctx, subset, idx);
        ECPoint expected = ctx.getGenerator().multiply(r[1]).normalize();
        assertEquals(
                "Reconstructed EC-point must be s·G",
                expected, Srec);
    }

    /**
     * Test the “mask/unmask” step in NAP-DKG.
     */
    @Test
    public void testMaskedShare() {
        Share share = GShamirShareDKG.generateShares(ctx, r[2])[2]; // pick party #3’s share

        // mask
        BigInteger cHat = MaskedShareCHat.compute(share.getAi(), share.getai(), ctx);

        System.out.println(cHat);
        // unmask
        BigInteger unmask = MaskedShareCHat.unmask(share.getAi(), cHat, ctx);
        assertEquals(
                "After masking then unmasking, we recover the original scalar share",
                share.getAi(), unmask);
    }

    /**
     * Test the first‐round hash‐polynomial derivation
     * (HashingTools.deriveFirstRoundPoly).
     * You can compare its output length (t+1) and maybe some known properties.
     */
    @Test
    public void testFirstRoundPoly() {
        // prepare all public inputs
        ECPoint[] pkj = new ECPoint[n];
        ECPoint[] Cij = new ECPoint[n];
        BigInteger[] CHat = new BigInteger[n];
        BigInteger[] v = ctx.getV();

        // re‐derive first round commitments
        Share[] shares = GShamirShareDKG.generateShares(ctx, r[0]);
        for (int i = 0; i < n; i++) {
            DhKeyPair kp = ephKeyPairs[i];
            pkj[i] = kp.getPublic();
            Cij[i] = kp.getPublic().multiply(kp.getSecretKey())
                    .add(shares[i].getAi())
                    .normalize();
            CHat[i] = MaskedShareCHat.compute(shares[i].getAi(), shares[i].getai(), ctx);
        }

        BigInteger[] poly = HashingTools.deriveFirstRoundPoly(
                ctx,
                ephKeyPairs[1].getPublic(),
                pkj, Cij, CHat,
                n, t);

        // it must be degree ≤ t, so length = t+1
        assertEquals("Hash‐poly length", t + 1, poly.length);
        // (you can add more invariants here)
    }
}
