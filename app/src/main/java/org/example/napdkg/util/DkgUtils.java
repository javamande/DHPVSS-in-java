// src/main/java/org/example/napdkg/util/DkgUtils.java
package org.example.napdkg.util;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.function.Predicate;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.example.napdkg.client.PbbClient;
import org.example.napdkg.core.NizkDlProof;
import org.example.napdkg.core.PublicKeysWithProofs;
import org.example.napdkg.core.Share;
import org.example.napdkg.dto.EphemeralKeyDTO;

public final class DkgUtils {
    public static final int POLL_MS = 100;

    private DkgUtils() {
        /* no-op */ }

    // —— point/scalar codecs —— //

    public static String encodePoint(ECPoint P) {
        return Hex.toHexString(P.normalize().getEncoded(true));
    }

    public static String encodeScalar(BigInteger x) {
        return x.toString(16);
    }

    public static String[] encodePoints(ECPoint[] pts) {
        String[] out = new String[pts.length];
        for (int i = 0; i < pts.length; i++) {
            out[i] = encodePoint(pts[i]);
        }
        return out;
    }

    public static String[] encodeScalars(BigInteger[] xs) {
        String[] out = new String[xs.length];
        for (int i = 0; i < xs.length; i++) {
            out[i] = encodeScalar(xs[i]);
        }
        return out;
    }

    /**
     * Polls the PBB every DEFAULT_POLL_MS until one DTO matching
     * `selector` appears, then applies `decoder` and returns the result.
     */
    // in DkgUtils.java
    public static <D, T> T waitForAndDecode(
            PbbClient pbb,
            String topic,
            Class<D> dtoClass,
            Predicate<D> selector,
            Function<D, T> decoder) throws Exception {
        while (true) {
            Thread.sleep(POLL_MS);
            for (D dto : pbb.fetch(topic, dtoClass)) {
                if (!selector.test(dto))
                    continue;
                return decoder.apply(dto);
            }
        }
    }

    public static ECPoint[] computeCommitments(
            DkgContext ctx,
            Share[] shares,
            List<PublicKeysWithProofs> pubs,
            BigInteger ski) {
        int n = shares.length;
        ECPoint[] Cij = new ECPoint[n];
        for (int j = 0; j < n; j++) {
            ECPoint Ej = pubs.get(j).getPublicKey();
            ECPoint Aij = shares[j].getAiPoint();
            Cij[j] = Ej.multiply(ski).add(Aij).normalize();
        }
        return Cij;
    }

    /** compute Ĉᵢⱼ = H′(Aᵢⱼ) ⊕ aᵢⱼ for all j */
    public static BigInteger[] computeMasks(
            DkgContext ctx,
            Share[] shares) {
        int n = shares.length;
        BigInteger[] CHat = new BigInteger[n];
        BigInteger order = ctx.getOrder();
        for (int j = 0; j < n; j++) {
            ECPoint Aij = shares[j].getAiPoint();
            BigInteger aij = shares[j].getai();
            CHat[j] = MaskedShareCHat.maskShare(Aij, aij, order);
        }
        return CHat;
    }

    /** aggregate U = ∑ vⱼ·Eⱼ, V = ∑ vⱼ·Cⱼⱼ */
    public static class Aggregation {
        public final ECPoint U, V;

        public Aggregation(ECPoint U, ECPoint V) {
            this.U = U;
            this.V = V;
        }
    }

    // public static Aggregation aggregateFirstRound(
    // DkgContext ctx,
    // List<PublicKeysWithProofs> pubs,
    // ECPoint[] Cij,
    // BigInteger[] CHat) {
    // BigInteger p = ctx.getOrder();
    // BigInteger[] α = ctx.getAlphas(), v = ctx.getVs();
    // ECPoint U = ctx.getGenerator().getCurve().getInfinity(),
    // V = U;
    // ECPoint pki = pubs.get(POLL_MS).getPublicKey();
    // ECPoint

    // for (int j = 1; j <= pubs.size(); j++) {
    // BigInteger f = EvaluationTools.evaluatePolynomial(
    // HashingTools.deriveFirstRoundPoly(ctx,
    // pki,
    // pubs.getPublicKey(),

    // Cij,
    // CHat,
    // pubs.size(),
    // ctx.getThreshold()),
    // α[j], p);
    // BigInteger w = v[j - 1].multiply(f).mod(p);
    // U = U.add(pubs.get(j - 1).getPublicKey().multiply(w)).normalize();
    // V = V.add(Cij[j - 1].multiply(w)).normalize();
    // }
    // return new Aggregation(U, V);
    // }

    // …plus a little helper to extract ECPoint[] from the list…
    private static ECPoint[] toArray(List<PublicKeysWithProofs> pubs) {
        ECPoint[] arr = new ECPoint[pubs.size()];
        for (int i = 0; i < arr.length; i++)
            arr[i] = pubs.get(i).getPublicKey();
        return arr;
    }

    public static List<PublicKeysWithProofs> fetchAllEphemeralPubs(
            DkgContext ctx, PbbClient pbb, int n) throws Exception {
        List<EphemeralKeyDTO> dtos = pbb.fetch("ephemeralKeys", EphemeralKeyDTO.class);
        List<PublicKeysWithProofs> pubs = new ArrayList<>(dtos.size());
        for (EphemeralKeyDTO dto : dtos) {
            byte[] raw = Hex.decode(dto.publicKey);
            ECPoint P = ctx.getGenerator()
                    .getCurve()
                    .decodePoint(raw)
                    .normalize();

            String[] parts = dto.schnorrProof.split("\\|");
            BigInteger challenge = new BigInteger(parts[0], 16);
            BigInteger response = new BigInteger(parts[1], 16);
            NizkDlProof proof = new NizkDlProof(challenge, response);
            Boolean verify = NizkDlProof.verifyProof(ctx, P, proof);
            if (verify == true) {
                pubs.add(new PublicKeysWithProofs(dto.partyIndex, P, proof));
            } else {
                throw new IllegalStateException("DL proof " + verify);
            }
        }
        // if you really want to _block_ until you have n, you can loop here
        return pubs;
    }

}
