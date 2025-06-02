package org.example.napdkg.core;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Predicate;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.example.napdkg.client.PbbClient;
import org.example.napdkg.core.NapDkgParty.ShareVerificationOutput;
import org.example.napdkg.dto.ShareVerificationOutputDTO;
import org.example.napdkg.dto.ThresholdKeyOutputDTO;
import org.example.napdkg.util.DkgContext;
import org.example.napdkg.util.DkgUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ThresHoldPhase {
    private static final Logger log = LoggerFactory.getLogger(ThresHoldPhase.class);
    private static final int POLL_MS = 100;
    private final PartyContext P;
    private final int fa;

    public ThresHoldPhase(PartyContext P, int fa) {
        this.P = P; // has P.id, P.ctx, P.pbb, P.ephKey
        this.fa = fa;
    }

    // in ThresholdPhase.java
    private <D, T> T waitForAndDecode(
            String topic,
            Class<D> dtoClass,
            Predicate<D> selector,
            Function<D, T> decoder) throws Exception {
        while (true) {
            Thread.sleep(POLL_MS);
            for (D dto : P.pbb.fetch(topic, dtoClass)) {
                if (!selector.test(dto))
                    continue;
                return decoder.apply(dto);
            }
        }
    }

    public ThresholdOutput fetchThresholdOutput(int dealerIndex) throws Exception {
        return waitForAndDecode(
                "ThresholdKeyOutput",
                ThresholdKeyOutputDTO.class,

                new Predicate<ThresholdKeyOutputDTO>() {
                    @Override
                    public boolean test(ThresholdKeyOutputDTO dto) {
                        return dto.dealerIndex == dealerIndex;
                    }
                },

                new Function<ThresholdKeyOutputDTO, ThresholdOutput>() {
                    @Override
                    public ThresholdOutput apply(ThresholdKeyOutputDTO dto) {
                        ECPoint tpki = P.ctx.getGenerator().getCurve()
                                .decodePoint(Hex.decode(dto.tpkiHex))
                                .normalize();
                        NizkDlEqProof prf = dto.proof.toProof();
                        return new ThresholdOutput(dto.dealerIndex, dto.partyIndex, tpki, prf);
                    }
                });
    }

    // in ThresholdPhase.java

    // Phase 3: Optimistic Threshold-Key for dealer i.
    public boolean doThresholdKey(int dealerIndex) throws Exception {

        PbbClient pbb = P.pbb;
        DkgContext ctx = P.ctx;
        int me = P.id;
        int t = P.t;

        // 1) Fetch that dealer’s SharingOutput (Cij[], CHat[], dealerPub, proof)

        // 2) Collect the first (t + fa) distinct ShareVerificationOutput for this
        // dealer
        int needed = t + fa;
        Map<Integer, ShareVerificationOutput> seen = new LinkedHashMap<>();
        while (seen.size() < needed) {
            Thread.sleep(100);
            // fetch _all_ published verification DTOs from the PBB
            List<ShareVerificationOutputDTO> dtos = pbb.fetch("ShareVerificationOutput",
                    ShareVerificationOutputDTO.class);

            for (ShareVerificationOutputDTO dto : dtos) {
                if (dto.verifierIndex != dealerIndex)
                    continue;
                if (seen.containsKey(dto.verifierIndex))
                    continue;

                // decode the share scalar
                BigInteger share = new BigInteger(dto.id, 16);

                // // decode the Cij points
                // ECPoint[] CijPts = new ECPoint[dto.CijHex.length];
                // for (int k = 0; k < dto.CijHex.length; k++) {
                // byte[] raw = Hex.decode(dto.CijHex[k]);
                // CijPts[k] = ctx.getGenerator().getCurve().decodePoint(raw).normalize();
                // }

                // seen.put(dto.verifierIndex,
                // new ShareVerificationOutput(dto.verifierIndex,
                // dto.verifierIndex,
                // share,
                // CijPts));

                // if (seen.size() >= needed)
                // break;
                // }
                // }
                List<Integer> Q1 = new ArrayList<>(seen.keySet());

                if (!Q1.contains(me)) {
                    Q1.add(me);
                }
                if (Q1.size() > needed) {
                    Q1 = Q1.subList(0, needed);
                }
                // the j’s we’ll sum over

                // 3) Fetch the ephemeral pubs E_j from Round 1
                List<PublicKeysWithProofs> pubs = DkgUtils.fetchAllEphemeralPubs(ctx, pbb, needed);

                // 4) Compute τ_pki = Σ_{j∈Q1} A_{i,j}, where A_{i,j} = G · a_{i,j}
                ECPoint tau_pki = ctx.getGenerator().getCurve().getInfinity();
                for (int j : Q1) {
                    BigInteger aij = seen.get(j).share;
                    ECPoint Aij = ctx.getGenerator().multiply(aij).normalize();
                    tau_pki = tau_pki.add(Aij).normalize();
                }

                // 5) Compute W_i = Σ_{j∈Q1} C_{i,j}
                ECPoint W_i = ctx.getGenerator().getCurve().getInfinity();
                for (int j : Q1) {
                    ShareVerificationOutput out = seen.get(j);
                    // out.Cij is already ECPoint[], decoded when you put it into seen
                    W_i = W_i.add(out.Cij[j]).normalize();
                }

                // 5) Compute W_i = Σ_{j∈Q1} C_{i,j}
                // ECPoint W_i = ctx.getGenerator().getCurve().getInfinity();
                // for (int j : Q1) {
                // W_i = W_i.add(seen.Cij[j]).normalize();
                // }

                // 6) Compute EQ1 = Σ_{j∈Q1} E_j
                ECPoint EQ1 = ctx.getGenerator().getCurve().getInfinity();
                for (int j : Q1) {
                    EQ1 = EQ1.add(pubs.get(j).getPublicKey()).normalize();
                }

                // 7) Form Δ = W_i − τ_pki
                ECPoint delta = W_i.subtract(tau_pki).normalize();

                // 8) Produce & verify the DLEQ proof that
                // log_G(Xi) == log_EQ1(delta),
                // where Xi = your own ephemeral pub G^{sk_me}, witness = sk_me.
                ECPoint Xi = P.ephKey.getPublic();
                BigInteger ski = P.ephKey.getSecretKey();
                // 1) generate & publish exactly one ThresholdOutput
                if (me == dealerIndex) {
                    // only the dealer “i” publishes its threshold‐key proof
                    log.info(
                            "▶ Threshold debug (dealer={}, party={}):\n" +
                                    "   tau_pki = {}\n" +
                                    "   W_i     = {}\n" +
                                    "   EQ1     = {}\n" +
                                    "   delta   = {}\n" +
                                    "   Xi      = {}",
                            dealerIndex, me,
                            DkgUtils.encodePoint(tau_pki),
                            DkgUtils.encodePoint(W_i),
                            DkgUtils.encodePoint(EQ1),
                            DkgUtils.encodePoint(delta),
                            DkgUtils.encodePoint(Xi));

                    NizkDlEqProof prf = NizkDlEqProof.generateProof(ctx, Xi, EQ1, delta, ski);
                    boolean ok = NizkDlEqProof.verifyProof(ctx, EQ1, Xi, delta, prf);

                    log.info(
                            "   → DLEQ proof: e={}  z={}  verify={}",
                            prf.getChallenge().toString(16),
                            prf.getResponse().toString(16),
                            ok);

                    ThresholdOutput out = new ThresholdOutput(dealerIndex, me, tau_pki, prf);
                    // ThresholdKeyOutputDTO dto = ThresholdKeyOutputDTO.from(out);
                    pbb.publish("ThresholdKeyOutput", dto);

                    return ok;
                } else {
                    // non‐dealers skip the heavy lifting and just report “ok”
                    return true;
                }

            }
        }
        return false;
    }
}