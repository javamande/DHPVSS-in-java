package org.example.napdkg.core;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.bouncycastle.math.ec.ECPoint;
import org.example.napdkg.client.PbbClient;
import org.example.napdkg.dto.ShareVerificationOutputDTO;
import org.example.napdkg.util.DkgContext;
import org.example.napdkg.util.DkgUtils;
import org.example.napdkg.util.MaskedShareCHat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles steps 5–7: collecting threshold outputs, verifying the final DLEQ
 * proofs,
 * and reconstructing the final secret share and group public key.
 */
public class ReconstructionPhase {

    private static final Logger log = LoggerFactory.getLogger(ReconstructionPhase.class);
    static final int POLL_MS = 100;
    private final PartyContext P;

    public ReconstructionPhase(PartyContext P) {
        this.P = P;

    }

    /**
     * Run steps 5–7 given the list of share-verification outputs Q1.
     */
    public void runReconstruction(List<SharingOutput> Q1) throws Exception {
        PbbClient pbb = P.pbb;
        int n = P.n;
        int t = P.t;
        int fa = P.fa;
        int me = P.id;
        int needed = t + fa;
        DkgContext ctx = P.ctx;
        BigInteger p = ctx.getOrder();
        ECPoint G = ctx.getGenerator();

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
        log.info("✅ Q2 is formed");

        Iterator<ShareVerificationPublish> it = Q2.iterator();
        while (it.hasNext()) {
            ShareVerificationPublish out = it.next();
            int j = out.verifierIndex;

            // 6.a) recompute W_j = Σ_{k∈Q1} C_{k,j}
            ECPoint Wj = G.getCurve().getInfinity();
            for (SharingOutput shDealer : Q1) {
                Wj = Wj.add(shDealer.Cij[j]).normalize();
            }

            // 6.b) recompute delta_j = W_j − τ_{pk_j}
            ECPoint deltaJ = Wj.subtract(out.tpki).normalize();

            // 6.c) fetch X_j = the ephemeral pub of party j
            ECPoint Ej = DkgUtils.fetchAllEphemeralPubs(ctx, pbb, n)
                    .get(j)
                    .getPublicKey();

            ECPoint EQ1 = G.getCurve().getInfinity();
            for (SharingOutput shj : Q1) {
                EQ1 = EQ1.add(shj.getDealerPub()).normalize();
            }
            // 6.d) verify DLEQ proof tying (G,X_j) to (EQ1, deltaJ)
            boolean ok = NizkDlEqProof.verifyProof(
                    ctx,
                    // base1, pub1
                    Ej, EQ1, deltaJ, // base2, pub2
                    out.Pftpki);

            if (!ok) {
                log.warn("Threshold proof invalid for party {}, removing from Q2", j);
                it.remove(); // drop this party from Q2
            } else {
                log.info("Threshold proof OK for party {}", j);
            }
            // 7) FINAL RECONSTRUCTION
            // 1) decrypt & unmask all A_{j,i} and collect scalar shares
            Map<Integer, ECPoint> Aij = new HashMap<>();
            Map<Integer, BigInteger> aij = new HashMap<>();
            BigInteger sk_i = P.ephKey.getSecretKey();

            for (SharingOutput shj : Q1) {
                int index = shj.dealerIndex;
                ECPoint Cji = shj.Cij[me]; // C_{j,i}
                ECPoint E = shj.dealerPub; // E_j

                // A_{j,i} = C_{j,i} − sk_i·E_j
                ECPoint Aji = Cji.subtract(E.multiply(sk_i)).normalize();
                Aij.put(index, Aji);

                // a_{j,i} = unmask( A_{j,i} , Ŝ_{j,i} )
                BigInteger ajiVal = MaskedShareCHat.unmaskShare(
                        Aji,
                        shj.getCHat()[me],
                        p);
                aij.put(j, ajiVal);
            }

            // 2) Build Share[] and int[] for Shamir‐reconstruction
            int m = Q1.size();
            Share[] shares = new Share[m];

            int[] indices = new int[m];

            for (int k = 0; k < m; k++) {
                int indexs = Q1.get(k).getDealerIndex();
                BigInteger a = aij.get(indexs);
                ECPoint A = Aij.get(indexs);

                shares[k] = new Share(a, A);
                indices[k] = indexs;
            }

            // 7b) Reconstruct x_i at 0 via Shamir‐interpolation
            ECPoint tpk = GShamirShareDKG.ShamirSharingResult.reconstructSecretEC(ctx, shares, indices);
            log.info("🎉 Reconstructed my final secret‐share x_i = {}", tpk.toString());

            // 7c) Compute the joint public key Y = Σ_{j∈Q2} τ_{pk_j}
            ECPoint Y = ctx.getGenerator().getCurve().getInfinity();
            for (ShareVerificationPublish outs : Q2) {
                Y = Y.add(outs.tpki).normalize();
            }
            log.info("🎉 Group public key Y = {}", Y);

        }
    }
}