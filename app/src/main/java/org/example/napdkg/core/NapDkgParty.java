package org.example.napdkg.core;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.function.Predicate;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.example.napdkg.client.PbbClient;
import org.example.napdkg.core.GShamirShareDKG.ShamirSharingResult;
import org.example.napdkg.dto.EphemeralKeyDTO;
import org.example.napdkg.dto.ShareVerificationOutputDTO;
import org.example.napdkg.dto.SharingOutputDTO;
import org.example.napdkg.util.DkgContext;
import org.example.napdkg.util.DkgUtils;
import org.example.napdkg.util.EvaluationTools;
import org.example.napdkg.util.GroupGenerator;
import org.example.napdkg.util.HashingTools;
import org.example.napdkg.util.MaskedShareCHat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class NapDkgParty {
    private static final Logger log = LoggerFactory.getLogger(NapDkgParty.class);
    private final int me;
    private final int n;
    private final int t;
    private final int fa;
    private final DkgContext ctx;
    private final PbbClient pbb;
    private final SecureRandom rnd = new SecureRandom();
    private DhKeyPair[] ephKeys;

    public NapDkgParty(int me, int n, int t, int fa, PbbClient pbb) {
        this.me = me;
        this.n = n;
        this.t = t;
        this.fa = fa;
        this.ctx = DHPVSS_Setup.dhPvssSetup(GroupGenerator.generateGroup(), t, n);
        this.pbb = pbb;
        this.ephKeys = new DhKeyPair[n];
    }

    /** Dealer’s output in Sharing (first round). */
    public static class SharingOutput {

        public int dealerIndex;
        public int publisherindex;
        public ECPoint dealerPub;

        public ECPoint[] Cij;
        public BigInteger[] CHat;
        public NizkDlEqProof proof;

        public SharingOutput(

                int dealerIndex,
                int publisherindex,
                ECPoint dealerPub,
                ECPoint[] Cij,
                BigInteger[] CHat,
                NizkDlEqProof proof) {

            this.dealerIndex = dealerIndex;
            this.dealerPub = dealerPub;
            this.Cij = Cij;
            this.CHat = CHat;
            this.proof = proof;
        }
    }

    /** Verifier’s output in Share-Verification (second round). */
    public static class ShareVerificationOutput {
        public final int dealerIndex, verifierIndex;
        public final BigInteger share;
        public final ECPoint[] Cij;

        public ShareVerificationOutput(int di, int verifierIndex, BigInteger share, ECPoint[] Cij) {
            this.dealerIndex = di;
            this.verifierIndex = verifierIndex;
            this.share = share;
            this.Cij = Cij;
        }
    }

    private static final int POLL_MS = 100;

    /**
     * Polls the PBB until one DTO matching `selector` appears, then
     * applies `decoder` to it and returns the domain‐object.
     */
    private <D, T> T waitForAndDecode(
            String topic,
            Class<D> dtoClass,
            Predicate<D> selector,
            Function<D, T> decoder) throws Exception {
        T result = null;
        while (result == null) {
            Thread.sleep(POLL_MS);
            for (D dto : pbb.fetch(topic, dtoClass)) {
                if (!selector.test(dto))
                    continue;
                result = decoder.apply(dto);
                break;
            }
        }
        return result;
    }

    /**
     * Block until we see a SharingOutput for the given dealerIndex on the PBB,
     * then return it.
     */
    private SharingOutput fetchSharingOutput(int dealerIndex) throws Exception {
        return waitForAndDecode(
                "DealerPublish",
                SharingOutputDTO.class,
                dto -> dto.dealerIndexDTO == dealerIndex,
                dto -> {
                    // decode dealerPub
                    ECPoint dealerPub = ctx.getGenerator()
                            .getCurve()
                            .decodePoint(Hex.decode(dto.dealerPub))
                            .normalize();
                    // decode Cij[]
                    ECPoint[] Cij = new ECPoint[dto.Cij.length];
                    for (int i = 0; i < Cij.length; i++) {
                        Cij[i] = ctx.getGenerator()
                                .getCurve()
                                .decodePoint(Hex.decode(dto.Cij[i]))
                                .normalize();
                    }
                    // decode CHat[]
                    BigInteger[] CHat = new BigInteger[dto.CHat.length];
                    for (int i = 0; i < CHat.length; i++) {
                        CHat[i] = new BigInteger(dto.CHat[i], 16);
                    }
                    // proof
                    NizkDlEqProof proof = dto.proof.toProof();
                    return new SharingOutput(dealerIndex, dealerIndex, dealerPub, Cij, CHat, proof);
                });
    }

    /**
     * Published by each party in Phase 3 (Threshold Key Computation).
     * Carries:
     * • dealerIndex: which dealer’s shares we’re reconstructing
     * • partyIndex: which verifier this is (i)
     * • τ_pki: the reconstructed EC‐point τ_{pki}
     * • W_i: the reconstructed scalar W_i
     */
    public static class ThresholdKeyOutput {
        public final int dealerIndex, partyIndex;
        public final ECPoint tpki;
        public final NizkDlEqProof prf;

        public ThresholdKeyOutput(int dealerIndex,
                int partyIndex,
                ECPoint tpki,
                NizkDlEqProof prf) {
            this.dealerIndex = dealerIndex;
            this.partyIndex = partyIndex;
            this.tpki = tpki;
            this.prf = prf;
        }
    }

    // in NapDkgParty.java
    public void runSetup() throws Exception {
        DhKeyPair kp = DhKeyPair.generate(ctx);
        ephKeys[me] = kp;
        String id = "id" + me;
        String Phex = DkgUtils.encodePoint(kp.getPublic());
        NizkDlProof proof = NizkDlProof.generateProof(ctx, kp);
        String proofHex = proof.getChallenge().toString(16)
                + "|" + proof.getResponse().toString(16);

        EphemeralKeyDTO dto = new EphemeralKeyDTO(id, me, Phex, proofHex);
        log.info("party " + me + " publishing its key");
        try {
            log.info("party " + me + " publishing its key");
            pbb.publish("ephemeralKeys", dto);
            log.info("party " + me + " published: " + dto);
        } catch (Exception ex) {
            log.info("party " + me + " publish failed:");
            ex.printStackTrace();
            throw ex;
        }

    }

    public void completeSetup() throws Exception {
        List<EphemeralKeyDTO> ephs;
        do {
            Thread.sleep(100);
            ephs = pbb.fetch("ephemeralKeys", EphemeralKeyDTO.class);
            log.info("party " + me + " sees " + ephs.size() + " keys");
        } while (ephs.size() < n);
        log.info("party " + me + " done waiting for " + n);
    }

    /**
     * Phase 1: Setup. Publish only your own ephemeral key+proof.
     * 
     * @throws Exception
     */

    /** Fetch exactly n ephemeral pubs (blocks until that many appear). */
    public List<PublicKeysWithProofs> fetchEph() throws Exception {
        // 1) fetch the JSON array of DTOs
        List<EphemeralKeyDTO> dtos = pbb.fetch("ephemeralKeys", EphemeralKeyDTO.class);

        List<PublicKeysWithProofs> pubs = new ArrayList<>();
        for (EphemeralKeyDTO dto : dtos) {
            // 2) decode the point
            byte[] raw = Hex.decode(dto.publicKey);
            ECPoint P = ctx.getGenerator().getCurve().decodePoint(raw).normalize();

            // 3) split the challenge|response and parse
            String[] parts = dto.schnorrProof.split("\\|");
            BigInteger challenge = new BigInteger(parts[0], 16);
            BigInteger response = new BigInteger(parts[1], 16);

            // 4) reconstruct the proof — note: we only need (challenge,response)
            NizkDlProof proof = new NizkDlProof(challenge, response);

            pubs.add(new PublicKeysWithProofs(dto.partyIndex, P, proof));
        }
        return pubs;
    }

    // 2 check proof for all public keys
    public List<PublicKeysWithProofs> getEphemeralPubs() throws Exception {
        return fetchEph();
    }

    public DkgContext getContext() {
        return ctx;
    }

    // ----------------------------------------------------------------
    // Phase 2: Sharing (as Dealer). : Sharing (1st round.)
    // ----------------------------------------------------------------
    public void runSharingAsDealer() throws Exception {
        BigInteger p = ctx.getOrder();
        ECPoint G = ctx.getGenerator();
        // 1. Sample ri ↔$ Z*p.
        BigInteger s = new BigInteger(p.bitLength(), rnd).mod(p);
        // 2. Run GshamirShareDkg to get get sh as ({Ai,j , ai,j }j↗[n]).
        ShamirSharingResult share = GShamirShareDKG.ShamirSharingResult.generateShares(ctx, s);
        Share[] sh = share.shares;

        // 2b) fetch all E₁…Eₙ
        List<PublicKeysWithProofs> eph = fetchEph();
        ECPoint[] E = new ECPoint[n];
        for (int j = 0; j < n; j++) {
            E[j] = eph.get(j).getPublicKey();
        }
        BigInteger sk_i = ephKeys[me].getSecretKey();
        ECPoint pk_i = ephKeys[me].getPublic();

        // 3. For all i →[n] compute Ci,j and Ĉᵢⱼ (that is H(Ai,j) xor aij)
        ECPoint[] Cij = new ECPoint[n];
        BigInteger[] CHat = new BigInteger[n];
        for (int j = 0; j < n; j++) {
            BigInteger aij = sh[j].getai();
            ECPoint Aij = sh[j].getAiPoint();
            // Compute Ci,j = Ej^ski + Ai,j
            Cij[j] = E[j].multiply(sk_i).add(Aij).normalize();
            // Compute C^i,j = H'(Aij) xor ai,j
            CHat[j] = MaskedShareCHat.maskShare(Aij, aij, ctx.getOrder());
        }

        BigInteger[] α = ctx.getAlphas(); // [0,α₁…αₙ]
        BigInteger[] v = ctx.getVs(); // [v₁…vₙ]
        // 4. optain m* from <- H(pki, pkj(E), Ci,j, C^i,j)
        BigInteger[] mStar = HashingTools.deriveMStar(
                ctx, pk_i, E, Cij, CHat, n, t);

        // 5. Start with U and V as identity element, that is getinfinity.
        ECPoint U = G.getCurve().getInfinity();
        ECPoint V = U;

        // Set U and V
        for (int j = 1; j <= n; j++) {
            // evaluate polynomila m*(alphaj)
            BigInteger eval = EvaluationTools.evaluatePolynomial(mStar, α[j], p);
            // w = m*(alphaj) * vj
            BigInteger w = v[j - 1].multiply(eval).mod(p);
            // U = Ej * w
            U = U.add(E[j - 1].multiply(w)).normalize();
            // V = Cij * w
            V = V.add(Cij[j - 1].multiply(w)).normalize();
        }

        // 2f) raw check & DLEQ
        // log.info(" dealer raw V==[sk]U? " + V.equals(U.multiply(sk_i)));

        // 6. Compute PfShi <- DLEQ(ski: G, pki, U, V)
        // log.info(" dealer raw V==[skᵢ]U? " + V.equals(U.multiply(sk_i)));
        NizkDlEqProof prf = NizkDlEqProof.generateProof(ctx, pk_i, U, V, sk_i);
        log.info(" dealer DLEQ ok? " +
                NizkDlEqProof.verifyProof(ctx, U, pk_i, V, prf));

        // Publish encrypted share vector Shi = ({Ci,j , C^i,j : i in [n]}, PfShi) on
        // PBB

        // … inside runSharingAsDealer(), instead of publishing the raw SharingOutput:

        org.example.napdkg.core.SharingOutput out = new org.example.napdkg.core.SharingOutput(me, me, pk_i, Cij, CHat,
                prf);
        // ← use the static factory
        SharingOutputDTO dto = SharingOutputDTO.from(out);
        pbb.publish("DealerPublish", dto);
    }

    /**
     * Round 2 (Share Verification) + Threshold Key Computation (optimistic).
     *
     * @param dealerIndex the index i of the dealer whose SharingOutput we
     *                    are verifying and reconstructing
     * @return the reconstructed Share S_i = (s, G^s)
     */

    // ------------Share Verification (2nd round or after t + fa parties post Shi on
    // PBB.)----------------------------------------------------
    public void runSharingAsVerifier(int dealerIndex) throws Exception {
        // Let Q₁ be the set of indices j such that Pⱼ are the first t+fₐ
        // parties to publish Sⱼ on the PBB.
        // All parties Pi : i →[n] parse Shj as ({Cj,k ,Cj,k : k →[n]}, PfShj ) for all
        // j in Q1, parse pkk as (Ek , proofk ) for all k →[n], and proceed as follows

        // → here we spin until we see the dealer’s SharingOutput Shᵢ,
        SharingOutput so = null;
        List<SharingOutputDTO> dtoList = null;
        // loop that will keep spinning until one SharingOutput arrives. checks every
        // 100 ms.
        // 1) Wait for exactly one SharingOutput from dealer i
        while (so == null) {
            Thread.sleep(100);

            dtoList = pbb.fetch("DealerPublish", SharingOutputDTO.class);
            for (SharingOutputDTO dto : dtoList) {
                // We don't want to fetch our own dealer index, as we know this
                if (dto.publisherindexDTO != dealerIndex)
                    continue;
                // decode the DTO back to domain SharingOutput:
                ECPoint dealerPub = ctx.getGenerator()
                        .getCurve()
                        .decodePoint(Hex.decode(dto.dealerPub));
                ECPoint[] Cij = new ECPoint[n];
                for (int j = 0; j < n; j++) {
                    Cij[j] = ctx.getGenerator()
                            .getCurve()
                            .decodePoint(Hex.decode(dto.Cij[j]));
                }
                BigInteger[] CHat = new BigInteger[n];
                for (int j = 0; j < n; j++) {
                    CHat[j] = new BigInteger(dto.CHat[j], 16);
                }
                // reconstruct the proof object
                NizkDlEqProof prf = dto.proof.toProof();
                so = new SharingOutput(dealerIndex, dealerIndex, dealerPub, Cij, CHat, prf);
                break;
            }
        }
        // Fetch E₁…Eₙ from Round 1.
        List<PublicKeysWithProofs> pubs = getEphemeralPubs();
        ECPoint[] E = new ECPoint[n];
        for (int j = 0; j < n; j++) {
            E[j] = pubs.get(j).getPublicKey();
        }

        // 1) RE-DERIVE m*(x) using the correct dealerPub seed
        BigInteger[] mStar = HashingTools.deriveMStar(
                ctx,
                so.dealerPub, // <-- the key you _seeded_ on the dealer side
                E,
                so.Cij,
                so.CHat,
                n, t);

        // 2) recompute Ucalc, Vcalc
        BigInteger p = ctx.getOrder();
        BigInteger[] alpha = ctx.getAlphas(); // [0, α₁…αₙ]
        BigInteger[] lambda = ctx.getVs(); // Lagrange-at-0 weights
        ECPoint Ucalc = ctx.getGenerator().getCurve().getInfinity();
        ECPoint Vcalc = Ucalc;
        for (int j = 1; j <= n; j++) {
            BigInteger f = EvaluationTools.evaluatePolynomial(mStar, alpha[j], p);
            BigInteger w = lambda[j - 1].multiply(f).mod(p);
            Ucalc = Ucalc.add(E[j - 1].multiply(w)).normalize();
            Vcalc = Vcalc.add(so.Cij[j - 1].multiply(w)).normalize();
        }

        // 3) now check the DLEQ proof that log_G(Ucalc) == log_{dealerPub}(Vcalc)
        if (!NizkDlEqProof.verifyProof(ctx, Ucalc, so.dealerPub, Vcalc, so.proof)) {
            throw new IllegalStateException("dealer DLEQ failed");
        }

        // If PfShj is not valid w.r.t G, pkj , U, V , remove j from Q1

        // else proceed
        // log.info("✅ Dealer’s DLEQ verified");

        // 4) Compute A→j,i ↔Cj,i↗ski·Ej and a→j,i ↔ˆCj,i ⇒H→(Aj,i).

        BigInteger sk_i = ephKeys[me].getSecretKey();
        // lastAPoints = new ECPoint[n];
        // lastCij = so.Cij;
        // BigInteger[] aij = new BigInteger[n];

        // inside runSharingAsVerifier(int dealerIndex):
        ECPoint dealerPub = so.dealerPub; // E_i = G^s_i from dealer
        ECPoint Cmine = so.Cij[me]; // C_{i,me}
        BigInteger CHatMine = so.CHat[me]; // mask for your share

        // 1) decrypt your commitment
        ECPoint A_me = Cmine.subtract(dealerPub.multiply(sk_i)).normalize();

        // 2) un-mask to get your scalar share
        BigInteger a_me = MaskedShareCHat.unmaskShare(
                A_me, CHatMine, ctx.getOrder());

        // 3) consistency check
        if (!ctx.getGenerator().multiply(a_me).equals(A_me)) {
            throw new IllegalStateException("Share mismatch for me=" + me);
        }

        ShareVerificationPublish Shareverifcation = new ShareVerificationPublish(me, A_me, so.proof);

        ShareVerificationOutputDTO svDto = ShareVerificationOutputDTO.from(Shareverifcation);
        pbb.publish("ShareVerificationOutput", svDto);

        // // 4) publish your one ShareVerificationOutput
        // pbb.publish("ShareVerificationOutput", new
        // ShareVerificationOutput(dealerIndex, me, a_me, so.Cij));
        // // log.info("Party " + me +
        // // ": verified share for dealer " + dealerIndex);

    }

    /**
     * // * Phase 3: Optimistic Threshold-Key for dealer i.
     * // * Returns true iff the final DLEQ proof checks out.
     * //
     */
    // public boolean doThresholdKey(int dealerIndex) throws Exception {
    // // 1) Fetch that dealer’s SharingOutput (Cij[], CHat[], dealerPub, proof)
    // SharingOutput so = fetchSharingOutput(dealerIndex);

    // // 2) Collect the first (t + fa) distinct ShareVerificationOutput for this
    // // dealer
    // int needed = t + fa;
    // Map<Integer, ShareVerificationOutput> seen = new LinkedHashMap<>();
    // while (seen.size() < needed) {
    // Thread.sleep(100);
    // // fetch _all_ published verification DTOs from the PBB
    // List<ShareVerificationOutputDTO> dtos = pbb.fetch("ShareVerificationOutput",
    // ShareVerificationOutputDTO.class);

    // for (ShareVerificationOutputDTO dto : dtos) {
    // if (dto.dealerIndex != dealerIndex)
    // continue;
    // if (seen.containsKey(dto.verifierIndex))
    // continue;

    // // decode the share scalar
    // BigInteger share = new BigInteger(dto.shareHex, 16);

    // // decode the Cij points
    // ECPoint[] CijPts = new ECPoint[dto.CijHex.length];
    // for (int k = 0; k < dto.CijHex.length; k++) {
    // byte[] raw = Hex.decode(dto.CijHex[k]);
    // CijPts[k] = ctx.getGenerator().getCurve().decodePoint(raw).normalize();
    // }

    // seen.put(dto.verifierIndex,
    // new ShareVerificationOutput(dto.dealerIndex,
    // dto.verifierIndex,
    // share,
    // CijPts));

    // if (seen.size() >= needed)
    // break;
    // }
    // }
    // List<Integer> Q1 = new ArrayList<>(seen.keySet()); // the j’s we’ll sum over

    // // 3) Fetch the ephemeral pubs E_j from Round 1
    // List<PublicKeysWithProofs> pubs = getEphemeralPubs();

    // // 4) Compute τ_pki = Σ_{j∈Q1} A_{i,j}, where A_{i,j} = G · a_{i,j}
    // ECPoint tau_pki = ctx.getGenerator().getCurve().getInfinity();
    // for (int j : Q1) {
    // BigInteger aij = seen.get(j).share;
    // ECPoint Aij = ctx.getGenerator().multiply(aij).normalize();
    // tau_pki = tau_pki.add(Aij).normalize();
    // }

    // // 5) Compute W_i = Σ_{j∈Q1} C_{i,j}
    // ECPoint W_i = ctx.getGenerator().getCurve().getInfinity();
    // for (int j : Q1) {
    // W_i = W_i.add(so.Cij[j]).normalize();
    // }

    // // 6) Compute EQ1 = Σ_{j∈Q1} E_j
    // ECPoint EQ1 = ctx.getGenerator().getCurve().getInfinity();
    // for (int j : Q1) {
    // EQ1 = EQ1.add(pubs.get(j).getPublicKey()).normalize();
    // }

    // // 7) Form Δ = W_i − τ_pki
    // ECPoint delta = W_i.subtract(tau_pki).normalize();

    // // 8) Produce & verify the DLEQ proof that
    // // log_G(Xi) == log_EQ1(delta),
    // // where Xi = your own ephemeral pub G^{sk_me}, witness = sk_me.
    // ECPoint Xi = ephKeys[me].getPublic();
    // BigInteger ski = ephKeys[me].getSecretKey();

    // log.info(
    // "▶ Threshold debug (dealer={}, party={}):\n" +
    // " tau_pki = {}\n" +
    // " W_i = {}\n" +
    // " EQ1 = {}\n" +
    // " delta = {}\n" +
    // " Xi = {}",
    // dealerIndex, me,
    // DkgUtils.encodePoint(tau_pki),
    // DkgUtils.encodePoint(W_i),
    // DkgUtils.encodePoint(EQ1),
    // DkgUtils.encodePoint(delta),
    // DkgUtils.encodePoint(Xi));
    // NizkDlEqProof prf = NizkDlEqProof.generateProof(ctx, Xi, EQ1, delta, ski);
    // boolean ok = NizkDlEqProof.verifyProof(ctx, EQ1, Xi, delta, prf);

    // log.info(
    // " → DLEQ proof: e={} z={} verify={}",
    // prf.getChallenge().toString(16),
    // prf.getResponse().toString(16),
    // ok);

    // ThresholdOutput ThresholdOutput = new ThresholdOutput(dealerIndex, me,
    // tau_pki, prf);

    // ThresholdKeyOutputDTO tkDto = ThresholdKeyOutputDTO.from(ThresholdOutput);
    // pbb.publish("ThresholdKeyOutput", tkDto);

    // // // 9) Publish and return
    // // pbb.publish("ThresholdKeyOutput", new ThresholdKeyOutput(dealerIndex, me,
    // // tau_pki, prf));
    // // // log.info("Party " + me +
    // // // ": Phase 3 (dealer " + dealerIndex + ") DLEQ ok? " + ok);
    // return ok;
    // }

}