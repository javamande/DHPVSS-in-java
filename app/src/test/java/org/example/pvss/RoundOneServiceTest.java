package org.example.pvss;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.Before;
import org.junit.Test;

public class RoundOneServiceTest {

    private static final int N = 20;
    private static final int T = 10;

    private DhPvssContext ctx;
    private InMemoryPbbClient pbb;
    private DhKeyPair[] ephKeyPairs;
    private EphemeralKeyPublic[] epkWrapped;
    private SecureRandom rnd;

    @Before
    public void setUp() throws NoSuchAlgorithmException {
        // 1) build group + context
        GroupGenerator.GroupParameters gp = GroupGenerator.generateGroup();
        ctx = DHPVSS_Setup.dhPvssSetup(gp, T, N);

        // 2) in‐mem PBB
        pbb = new InMemoryPbbClient("http://localhost:3000");

        // 3) generate N ephemeral keypairs + wrap in proof
        rnd = new SecureRandom();
        ephKeyPairs = new DhKeyPair[N];
        epkWrapped = new EphemeralKeyPublic[N];
        for (int i = 0; i < N; i++) {
            DhKeyPair kp = DhKeyPair.generate(ctx);
            ephKeyPairs[i] = kp;
            NizkDlProof proof = NizkDlProof.generateProof(ctx, kp);
            epkWrapped[i] = new EphemeralKeyPublic(kp.getPublic(), proof);
        }
    }

    @Test
    public void testPublishEphemeralKeys() throws Exception {
        // nothing in PBB yet
        assertTrue(pbb.getStored().isEmpty());

        // call the service
        RoundOneService.publishEphemeralKeys(pbb, ctx, ephKeyPairs, epkWrapped);

        // after, PBB should contain exactly one batch of N EphemeralKeyPublics
        List<Object> store = pbb.getStored();

        Object batch = store.get(0);
        // List<Object> all = store.getStored();
        assertEquals("should have published an EphemeralKeyPublic[]", 1, store.size());
        assertTrue(store.get(0) instanceof EphemeralKeyPublic[]);
        assertSame(epkWrapped, store.get(0));

        EphemeralKeyPublic[] loaded = (EphemeralKeyPublic[]) batch;
        assertEquals(N, loaded.length);
        for (int i = 0; i < N; i++) {
            assertNotNull(loaded[i].getPublicKey());
            assertNotNull(loaded[i].getProof());
            // and the public in store matches the one we generated
            assertEquals(ephKeyPairs[i].getPublic(), loaded[i].getPublicKey());
        }
        assertEquals(N, loaded.length);
    }

    @Test
    public void testShareRoundOneAppendsShares() throws Exception {
        // first we must publish ephemeral keys so that shareRoundOne can read them
        RoundOneService.publishEphemeralKeys(pbb, ctx, ephKeyPairs, epkWrapped);

        // now sample secrets & run shareRoundOne
        BigInteger[] secrets = RoundOneService.sampleSecrets(ctx, rnd);
        RoundOneService.shareRoundOne(pbb, ctx, ephKeyPairs, secrets);

        // now PBB should have two entries: [0]=epk batch, [1]=ShareMessage batch
        List<Object> store = pbb.getStored();
        assertEquals("two batches: keys and then shares", 2, store.size());

        Object maybeShares = store.get(1);
        assertTrue(
                "round-1 share output should be a ShareMessage[]", maybeShares instanceof ShareMessage[]);

        ShareMessage[] shares = (ShareMessage[]) maybeShares;
        assertEquals(
                "should have produced exactly N encrypted‐share structs", N, shares.length);

        // simple sanity on each ShareMessage
        for (int i = 0; i < N; i++) {
            ShareMessage m = shares[i];
            assertNotNull("Ci→* array must be non‐null", m.getEncryptedShares());
            assertNotNull("Ĉi→* array must be non‐null", m.getMaskedShares());
            assertNotNull("each must carry a DLEQ proof", m.getProof());
            // each encrypted‐share array is length N
            assertEquals(N, m.getEncryptedShares().length);
            assertEquals(N, m.getMaskedShares().length);
        }
    }

    @Test
    public void testPublishEphemeralKeys1() throws Exception {
        // no messages yet
        assertTrue("PBB should start empty", pbb.getStored().isEmpty());

        // call the service
        RoundOneService svc = new RoundOneService(pbb, ctx);
        svc.publishEphemeralKeys(epkWrapped);

        // exactly one publication
        List<Object> store = pbb.getStored();
        assertEquals("should have published exactly one batch", 1, store.size());

        // that first entry is the full array of EphemeralKeyPublic
        Object batch = store.get(0);
        assertTrue("expected EphemeralKeyPublic[]", batch instanceof EphemeralKeyPublic[]);

        EphemeralKeyPublic[] loaded = (EphemeralKeyPublic[]) batch;
        assertEquals("array length must be N", N, loaded.length);

        // each one round‐trips correctly
        for (int i = 1; i < N; i++) {
            // same public key object
            ECPoint gotPub = loaded[i].getPublicKey();
            ECPoint wantPub = ephKeyPairs[i].getPublic();
            assertEquals("public‐key mismatch at index " + i, wantPub, gotPub);

            // proof is non‐null and verifies
            NizkDlProof p = loaded[i].getProof();
            assertNotNull("proof should be non‐null", p);
            assertTrue("proof should verify", NizkDlProof.verifyProof(ctx, wantPub, p));
        }

    }

    @Test
    public void testRecoverRawShamirShares() throws Exception {
        // 1) do round 1 ephemeral‐key publication
        RoundOneService.publishEphemeralKeys(pbb, ctx, ephKeyPairs, epkWrapped);

        // 2) sample secrets and do share‐round
        BigInteger[] r = RoundOneService.sampleSecrets(ctx, rnd);
        RoundOneService.shareRoundOne(pbb, ctx, ephKeyPairs, r);

        // 3) grab the ShareMessage[] batch off our in‐mem PBB
        Object maybeShares = pbb.getStored().get(1);
        assertTrue(maybeShares instanceof ShareMessage[]);
        ShareMessage[] batch = (ShareMessage[]) maybeShares;

        // 4) recover every scalar ai→j
        BigInteger[][] recovered = RoundOneService.recoverSecretShares(ctx, ephKeyPairs, batch);

        // 5) for each dealer i, recompute its *expected* vector of shares directly
        for (int dealer = 0; dealer < N; dealer++) {
            // this re‐runs your Shamir‐share code for secret r[dealer]
            Share[] expected = GShamirShareDKG.generateShares(ctx, r[dealer]);

            for (int receiver = 0; receiver < N; receiver++) {
                // compare the recovered scalar with the expected one
                assertEquals(
                        "dealer=" + dealer + "→receiver=" + receiver,
                        expected[receiver].getAi(), // the polynomial‐evaluation scalar
                        recovered[dealer][receiver]);
            }
        }
    }

    @Test
    public void testComputeFirstRoundForParty() throws Exception {

        GroupGenerator.GroupParameters gp = GroupGenerator.generateGroup();
        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(gp, T, N);

        // 2) in‐mem PBB
        InMemoryPbbClient pbb = new InMemoryPbbClient("http://localhost:3000");

        // 3) generate N ephemeral keypairs + wrap in proof
        SecureRandom rnd = new SecureRandom();
        DhKeyPair[] ephKeyPairs = new DhKeyPair[N];
        EphemeralKeyPublic[] epkWrapped = new EphemeralKeyPublic[N];
        for (int i = 0; i < N; i++) {
            DhKeyPair kp = DhKeyPair.generate(ctx);
            ephKeyPairs[i] = kp;
            NizkDlProof proof = NizkDlProof.generateProof(ctx, kp);
            epkWrapped[i] = new EphemeralKeyPublic(kp.getPublic(), proof);
        }
        PartyOneOutput out = PartyOneOutput.computeFirstRoundForParty(ctx,
                ephKeyPairs[3], ephKeyPairs, BigInteger.valueOf(3));

        assertEquals(ctx.getNumParticipants(), out.getCij().length);
        assertEquals(ctx.getNumParticipants(), out.getCht().length);
        assertTrue(
                NizkDlEqProof.verifyProof(
                        ctx, out.getU(), ephKeyPairs[3].getPublic(), out.getV(), out.getProof()));
    }

    public static void main(String[] args) throws Exception {

        RoundOneServiceTest test = new RoundOneServiceTest();
        test.testComputeFirstRoundForParty();
    }

}
