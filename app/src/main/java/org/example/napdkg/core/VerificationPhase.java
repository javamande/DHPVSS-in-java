package org.example.napdkg.core;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.example.napdkg.client.PbbClient;
import org.example.napdkg.dto.ShareVerificationOutputDTO;
import org.example.napdkg.dto.SharingOutputDTO;
import org.example.napdkg.util.DkgContext;
import org.example.napdkg.util.DkgUtils;
import org.example.napdkg.util.EvaluationTools;
import org.example.napdkg.util.HashingTools;
import org.example.napdkg.util.MaskedShareCHat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class VerificationPhase {
    private static final Logger log = LoggerFactory.getLogger(VerificationPhase.class);

    static final int POLL_MS = 100;

    private final PartyContext P;
    private final DkgContext ctx;
    private final PbbClient pbb;
    private final int me, n, t, fa;
    private final ECPoint G;
    private List<SharingOutput> Q1 = new ArrayList<>();
    private Map<Integer, ECPoint> Aij = new HashMap<>();
    private Map<Integer, BigInteger> aij = new HashMap<>();
    private ECPoint trueGroupKey = null;

    // 2) setter
    public void setTrueGroupKey(ECPoint trueGroupKey) {
        this.trueGroupKey = trueGroupKey;
    }

    public int getMe() {
        return me;
    }

    // 3) getter
    public ECPoint getTrueGroupKey() {
        return this.trueGroupKey;
    }

    public List<SharingOutput> getQ1() {
        // return a copy to avoid external mutation
        return Collections.unmodifiableList(Q1);
    }

    // Once per‐party: your reconstructed x_i & τ_pki
    // private BigInteger reconstructedShare;
    private ECPoint tauPki;
    private NizkDlEqProof thresholdProof;

    public VerificationPhase(PartyContext P) {
        this.P = P;
        this.ctx = P.ctx;
        this.pbb = P.pbb;
        this.me = P.id;
        this.n = P.n;
        this.t = P.t;
        this.fa = P.fa;
        this.G = ctx.getGenerator();
    }

    // public List<EphemeralKeyPublic> getEphemeralPubs() throws Exception {
    // return SharingPhase.fetchEph();
    // }
    /** Top-level: do the whole threshold phase in order, once. */
    public void runThresholdPhase() throws Exception {
        // 1) collect & verify exactly t+fa dealers into Q1

        // 2) publish your own threshold output Θ_i

        // // 3) collect first t+fa threshold-outputs Θ_j and prune bad proofs → Q2
        // List<ShareVerificationPublish> Q2 = collectAndPruneThresholdOutputs();
        // log.info("✅ Q2 formed ({} parties)", Q2.size());

        // // 4) do the final Shamir reconstruction
        // finalReconstruction(Q1, Q2);
    }

    /**
     * Round 2 (Share Verification) Threshold Key Computation (optimistic).
     * 
     * @param dealerToVerify index for the dealer we are currently verifying.
     * @return the reconstructed Share S_i = (s, G^s)
     * @throws Exception
     * @throws IOException
     */

    private SharingOutput fetchAndCollectDealer(int dealerToVerify) throws IOException, Exception {
        SharingOutput so = null;
        while (so == null) {
            Thread.sleep(POLL_MS);
            for (SharingOutputDTO dto : pbb.fetch("DealerPublish", SharingOutputDTO.class)) {
                if (dto.dealerIndexDTO != dealerToVerify)
                    continue;
                so = SharingOutput.fromDTO(dto, ctx);
                System.out.printf("✔ Collected Sh_%d%n", dealerToVerify);
                break;
            }
        }
        return so;
    }

    // ------------Share Verification (2nd round or after t fa parties post Shi
    // PBB.)----------------------------------------------------
    public void VerifySharesFor(int dealerToVerify) throws Exception {
        // Let Q₁ be the set of indices j such that Pⱼ are the first t+fₐ
        // parties to publish Sᵢⱼ on the PBB.
        // → here we spin until we see the dealer’s SharingOutput Sᵢ,*

        SharingOutput so = fetchAndCollectDealer(dealerToVerify);
        SharingOutput CurrentDealer = so;
        boolean samedealer = true;
        if (CurrentDealer.dealerIndex == dealerToVerify) {
            samedealer = true;
        }
        System.out.println("is CurrentDealer == dealterToVerify??" + samedealer);

        // Fetch pkk for all j in |n| from PBB.
        List<PublicKeysWithProofs> pubs = DkgUtils.fetchAllEphemeralPubs(ctx, pbb, n);
        ECPoint[] E = new ECPoint[n];
        // All public key = pk_k as public keys.
        for (int j = 0; j < n; j++) {
            E[j] = pubs.get(j).getPublicKey();
        }

        // 1) RE-DERIVE m*(x) using the correct dealerPub seed
        BigInteger[] mStar = HashingTools.deriveMStar(
                ctx,
                CurrentDealer.dealerPub, // <-- the key pkj from the dealer we want to verify
                E,
                CurrentDealer.Cij,
                CurrentDealer.CHat,
                n, t);

        System.out.println("Verifier computed mStar: " + Arrays.toString(mStar));

        log.info(mStar + "Is formed");

        // 2) recompute (U,V))
        BigInteger p = ctx.getOrder();
        BigInteger[] alpha = ctx.getAlphas(); // [0, α₁…αₙ]
        BigInteger[] lambda = ctx.getVs();
        // Lagrange-at-0 weights
        ECPoint U = G.getCurve().getInfinity();
        ECPoint V = G.getCurve().getInfinity();
        for (int j = 1; j <= n; j++) {
            BigInteger f = EvaluationTools.evaluatePolynomial(mStar, alpha[j], p);
            // w = vk * m*(alphak)
            BigInteger w = lambda[j - 1].multiply(f).mod(p);
            // U = Ek * w
            U = U.add(E[j - 1].multiply(w)).normalize();
            V = V.add(CurrentDealer.Cij[j - 1].multiply(w)).normalize();
        }

        // 3) now check the DLEQ proof that log_G(Ucalc) == log_{dealerPub}(Vcalc)
        if (!NizkDlEqProof.verifyProof(ctx, CurrentDealer.dealerPub, U, V, CurrentDealer.proof)) {
            log.info("dealer DLEQ failed{}", dealerToVerify);

            for (int i = 0; i < Q1.size(); i++) {
                if (Q1.get(i).getDealerIndex() == dealerToVerify) {
                    Q1.remove(i);
                    i--; // step back one so we don't skip next item
                }

            }
            return; // done verifying this dealer
        } else {
            log.info("DLEQ SUCCESS for dealer {}", dealerToVerify);
            // If this dealer not already in Q1, add it:
            boolean alreadyInQ1 = false;
            for (SharingOutput x : Q1) {
                if (x.getDealerIndex() == dealerToVerify) {
                    alreadyInQ1 = true;
                    break;
                }
            }
            if (!alreadyInQ1) {
                Q1.add(CurrentDealer);
            }
        }

        // If PfShj is not valid w.r.t G, pkj , U, V , remove j from Q1

        // else proceed
        // log.info("✅ Dealer’s DLEQ verified");

        // 4) Compute A→j,i ↔Cj,i↗ski·Ej and a→j,i ↔ˆCj,i ⇒H→(Aj,i).

        BigInteger sk_i = P.ephKey.getSecretKey();
        // lastAPoints = new ECPoint[n];
        // lastCij = so.Cij;
        // BigInteger[] aij = new BigInteger[n];

        // inside runSharingAsVerifier(int dealerIndex):
        ECPoint dealerPub = CurrentDealer.dealerPub; // E_j = G^s_i from dealer
        ECPoint Cmine = CurrentDealer.Cij[me]; // C_{i,me}
        BigInteger CHatMine = CurrentDealer.CHat[me]; // mask for your share

        // 1) decrypt your/as a verifer commitment
        ECPoint A_me = Cmine.subtract(dealerPub.multiply(sk_i)).normalize();

        // 2) un-mask to get your scalar share
        BigInteger a_me = MaskedShareCHat.unmaskShare(
                A_me, CHatMine, ctx.getOrder());
        // 1) for each dealer j ∈ Q1 decrypt & unmask your share

        for (SharingOutput shj : Q1) {
            int j = shj.getDealerIndex();
            // C_{j,i} is the commitment for party i from dealer j
            ECPoint Cji = shj.getCij()[me];
            BigInteger chi = shj.getCHat()[me];
            ECPoint Ej = shj.getDealerPub(); // E_j
            // A_{j,i} = C_{j,i} - sk_i · E_j
            ECPoint Aji = Cji.subtract(Ej.multiply(sk_i)).normalize();

            // a_{j,i} = unmask(A_{j,i})
            BigInteger ajiVal = MaskedShareCHat.unmaskShare(Aji, chi, p);

            // consistency check: G·a_{j,i} == A_{j,i}
            if (!G.multiply(ajiVal).normalize().equals(Aji)) {
                throw new IllegalStateException(
                        String.format("Bad share from dealer %d for me=%d", j, me));
            }
            this.Aij.put(j, Aji);
            this.aij.put(j, ajiVal);
        }

        // 3) consistency check
        if (!G.multiply(a_me).equals(A_me)) {
            log.info(
                    "A'j,i check failed!!! We should compute PfDecj,i ↔DLEQ(ski; G, Ei, Ej , Cj,i↗A→j,i) and PUBLISH COMPLAINT");
            throw new IllegalStateException("Share mismatch for me=" + me);
        }
        if (G.multiply(a_me).equals(A_me)) {
            log.info("A'j,i equals Cj,i - ski * Ej");
        }

    }

    // new method in VerificationPhase:
    public void publishThresholdOutput() throws Exception {

        // 1) recompute your tau_pki over the final Q1
        ECPoint tau = ctx.getGenerator().getCurve().getInfinity();
        for (ECPoint Aji : Aij.values()) {
            tau = tau.add(Aji).normalize();
        }

        this.tauPki = tau;

        // 2) recompute W_i = Σ_{j∈Q₁} C_{j,i}
        ECPoint Wi = ctx.getGenerator().getCurve().getInfinity();
        for (SharingOutput shj : Q1) {
            Wi = Wi.add(shj.getCij()[me]).normalize();
        }

        // 3) recompute EQ₁ = Σ_{j∈Q₁} Eₙ (dealers’ ephemeral pubs)
        ECPoint EQ1 = ctx.getGenerator().getCurve().getInfinity();
        for (SharingOutput shj : Q1) {
            EQ1 = EQ1.add(shj.getDealerPub()).normalize();
        }

        // 4) Δ = W_i − τ
        ECPoint delta = Wi.subtract(tau).normalize();

        // 8) Produce & verify the DLEQ proof that
        // log_G(Xi) == log_EQ1(delta),
        // where Ei = your own ephemeral pub G^{sk_me}, witness = sk_me.
        ECPoint Ei = P.ephKey.getPublic();
        // 1) generate & publish exactly one ThresholdOutput
        BigInteger sk_i = P.ephKey.getSecretKey();
        this.thresholdProof = NizkDlEqProof.generateProof(ctx, Ei, EQ1, delta, sk_i);
        boolean ok = NizkDlEqProof.verifyProof(ctx, Ei, EQ1, delta, thresholdProof);

        log.info(
                "   → DLEQ proof: e={}  z={}  verify={}",
                thresholdProof.getChallenge().toString(16),
                thresholdProof.getResponse().toString(16),
                ok);

        ShareVerificationPublish out = new ShareVerificationPublish(me, tauPki, thresholdProof);
        ShareVerificationOutputDTO dto = ShareVerificationOutputDTO.from(out);
        pbb.publish("ShareVerificationOutput", dto);
        log.info("→ DLEQ Θ_{}", me);

    }

    public List<ShareVerificationPublish> collectAndPruneThresholdOutputs() throws Exception {

        int needed = t + fa;

        // 1) collect the first t+fa distinct Θ_j

        // 5) Collect first t+fa threshold outputs Θ_i
        Map<Integer, ShareVerificationPublish> received = new HashMap<>();
        while (received.size() < needed) {
            Thread.sleep(VerificationPhase.POLL_MS);
            List<ShareVerificationOutputDTO> dtoList = pbb.fetch("ShareVerificationOutput",
                    ShareVerificationOutputDTO.class);
            for (ShareVerificationOutputDTO dto : dtoList) {
                int pi = dto.verifierIndex;
                if (!received.containsKey(pi)) {
                    ShareVerificationPublish out = ShareVerificationPublish.fromDTO(dto, P.ctx);
                    received.put(pi, out);
                    log.info("Collected Θ_{} ({}/{})", pi, received.size(), needed);
                }
                if (received.size() >= needed)
                    break;
            }
        }

        List<ShareVerificationPublish> Q2 = new ArrayList<>(received.values());
        log.info("✅ Q2 formed ({} parties)", Q2.size());

        // 2) recompute EQ1 = Σ_{k∈Q1} E_k (same as in publishThresholdOutput)
        ECPoint EQ1 = ctx.getGenerator().getCurve().getInfinity();
        for (SharingOutput shj : Q1) {
            EQ1 = EQ1.add(shj.getDealerPub()).normalize();
        }

        // 3) prune any Θ_j whose proof fails:
        Iterator<ShareVerificationPublish> it = Q2.iterator();
        while (it.hasNext()) {
            ShareVerificationPublish out = it.next();
            int j = out.verifierIndex;
            // compute W_j = Σ_{k∈Q1} C_{k,j}
            ECPoint Wj = G.getCurve().getInfinity();
            for (SharingOutput shj : Q1) {
                Wj = Wj.add(shj.getCij()[j]).normalize();
            }
            ECPoint deltaJ = Wj.subtract(out.tpki).normalize();
            // fetch ephemeral pub X_j
            ECPoint Xj = DkgUtils.fetchAllEphemeralPubs(ctx, pbb, n)
                    .get(j)
                    .getPublicKey();
            // verify DLEQ(G, Xj; EQ1, deltaJ)
            boolean ok = NizkDlEqProof.verifyProof(ctx, Xj, EQ1, deltaJ, out.Pftpki);
            if (!ok) {
                log.warn("↪ Threshold proof invalid for party {}, dropping from Q2", j);
                it.remove();
            } else {
                log.info("↪ Threshold proof OK for party {}", j);
            }
        }

        return Q2;
    }

    public void finalReconstruction(List<SharingOutput> Q1, List<ShareVerificationPublish> Q2) throws Exception {

        // STEP 6: prune bad Θ_j
        Iterator<ShareVerificationPublish> it = Q2.iterator();
        while (it.hasNext()) {
            ShareVerificationPublish out = it.next();
            int j = out.verifierIndex;

            // recompute W_j = Σ_{k∈Q1} C_{k,j}
            ECPoint Wj = G.getCurve().getInfinity();
            for (SharingOutput sh : Q1) {
                Wj = Wj.add(sh.getCij()[j]).normalize();
            }

            // 6.b) Δ_j = W_j − τ_{pk_j}
            ECPoint deltaJ = Wj.subtract(out.tpki).normalize();

            // 6.c) fetch X_j (the party’s ephemeral pub E_j)
            ECPoint Ej = DkgUtils.fetchAllEphemeralPubs(ctx, pbb, n)
                    .get(j)
                    .getPublicKey();

            ECPoint EQ1 = G.getCurve().getInfinity();
            for (SharingOutput shj : Q1) {
                EQ1 = EQ1.add(shj.getDealerPub()).normalize();
            }
            // 6.d) verify DLEQ(G, X_j; EQ1, Δ_j)

            boolean ok = NizkDlEqProof.verifyProof(
                    ctx,
                    Ej, // base1, pub1
                    EQ1, deltaJ, // base2, pub2
                    out.Pftpki);

            if (!ok) {
                log.warn("↪ Threshold proof invalid for party {}, dropping from Q2", j);
                it.remove();
            } else {
                log.info("↪ Threshold proof OK for party {}", j);
            }
        }
        // 7a) decrypt & unmask from Q1
        for (SharingOutput shj : Q1) {
            int j = shj.getDealerIndex();
            ECPoint Cji = shj.getCij()[me]; // C_{j,i}
            ECPoint Ej = shj.getDealerPub(); // E_j
            BigInteger sk_i = P.ephKey.getSecretKey();
            // A_{j,i} = C_{j,i} - sk_i · E_j
            ECPoint Aji = Cji.subtract(Ej.multiply(sk_i)).normalize();
            Aij.put(j, Aji);

            // a_{j,i} = unmask(A_{j,i}, Ŝ_{j,i})
            BigInteger chi = shj.getCHat()[me];
            BigInteger ajiV = MaskedShareCHat.unmaskShare(Aji, chi, ctx.getOrder());
            aij.put(j, ajiV);
        }
        // 7b) build the arrays for the Shamir call (CORRECT: use Q1, the dealers)
        int m = Q1.size();
        Share[] shares = new Share[m];
        int[] indices = new int[m];

        for (int k = 0; k < m; k++) {
            int j = Q1.get(k).getDealerIndex(); // dealer indices, which you *did* put into Aij/aij
            indices[k] = j;
            shares[k] = new Share(
                    aij.get(j), // non-null
                    Aij.get(j) // non-null
            );
        }

        // Something about lagrange and reconstruction
        int m2 = Q2.size();
        Share[] tpkShares = new Share[m2];
        int[] tpkIndices = new int[m2];

        for (int k = 0; k < m2; k++) {
            int j = Q2.get(k).verifierIndex; // index in [0..n−1]
            ECPoint Tpk_j = Q2.get(k).tpki; // this is G^{x_j}

            tpkIndices[k] = j + 1;
            // Wrap it in a Share object so we can reuse reconstructSecretEC():
            tpkShares[k] = new Share(BigInteger.ZERO, Tpk_j);
            // (we only care about getAiPoint(), so scalar is unused here)
        }

        // 7c) invoke the reconstructor
        // STEP 7c: reconstruct x_i
        ECPoint x_i = GShamirShareDKG.ShamirSharingResult.reconstructSecretEC(ctx, tpkShares, tpkIndices);
        log.info("🎉 Reconstructed x_i = {}", x_i.toString());

        // sanity-check G^x_i == τ_{pk_i}

        log.info("✓ G^x_i == τ_{pk_i}");

        log.info(" → Final reconstructed group‐key        = {}",
                Hex.toHexString(x_i.getEncoded(true)));
        log.info(" → Expected trueGroupKey from SmokeTest = {}", Hex.toHexString(trueGroupKey.getEncoded(true)));

        if (!x_i.equals(trueGroupKey)) {
            throw new IllegalStateException(
                    "Group‐key mismatch! reconstructed "
                            + Hex.toHexString(x_i.getEncoded(true))
                            + " but expected "
                            + Hex.toHexString(trueGroupKey.getEncoded(true)));
        }
        // STEP 7d: group key Y = Σ τ_{pk_j}

        log.info("🎉 reconstruction OK!");

        log.info("🎉 Group public key Y = {}", x_i);
    }

}
