// In DHPVSS_Decryption.java
package org.example.pvss;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

public class DhPvss_Decryption {

    /**
     * A decrypted share A_i together with a zero‑knowledge proof that it was
     * correctly extracted from the encrypted share.
     *
     * share = A_i ∈ 𝔾
     * proof is a non‑interactive proof of DLEQ demonstrating knowledge of x
     * such that
     * E_i = G^x and
     * Δ_i = pk_D^x
     * where E_i = G·sk_E,i and pk_D = G·sk_D.
     */
    public static class DecryptionShare {
        private final ECPoint share; // A_i
        private final NizkDlEqProof proof;

        public DecryptionShare(ECPoint share, NizkDlEqProof proof) {
            this.share = share;
            this.proof = proof;
        }

        /** @return the recovered share A_i = C_i − skE·pkD */
        public ECPoint getShare() {
            return share;
        }

        /** @return the DLEQ proof that log_G(E_i)==log_pkD(Δ_i) */
        public NizkDlEqProof getProof() {
            return proof;
        }
    }

    /**
     * Decrypts one encrypted share C_i = A_i + sk_D·E_i and proves correctness.
     *
     * Given:
     * – ctx : the DHPVSS context (ℤ_p order, generator G, etc.)
     * – pkD : dealer’s public key pk_D = G·sk_D
     * – E_i : participant’s ephemeral pub key E_i = G·sk_E
     * – skE : the corresponding ephemeral secret sk_E
     * – C_i : the encrypted share C_i = A_i + sk_D·E_i
     *
     * We compute:
     * Δ_i = sk_E · pk_D // = skE × (G·skD)
     * A_i = C_i − Δ_i // recover the group‑share
     *
     * Then we generate a non‑interactive DLEQ proof of x = sk_E for the relation:
     * E_i = G^x (i.e. E_i = G·skE)
     * Δ_i = pk_D^x (i.e. Δ_i = (G·skD)^skE = skE·pkD)
     *
     * @return both A_i and its proof of correct decryption
     */
    public static DecryptionShare decShare(
            DhPvssContext ctx,
            ECPoint pkD,
            ECPoint E_i,
            BigInteger skE,
            ECPoint C_i) {

        // 1) Compute Δ_i = skE · pkD
        ECPoint delta = pkD.multiply(skE).normalize();

        // 2) Recover the share A_i = C_i − Δ_i
        ECPoint A_i = C_i.subtract(delta).normalize();

        // 3) Prove that both E_i and Δ_i use the same exponent x = skE:
        // E_i = G^x
        // Δ_i = pkD^x
        NizkDlEqProof proof = NizkDlEqProof.generateProof(
                ctx,
                pkD, // base2 = pk_D = G·skD
                E_i, // h1 = E_i = G^skE
                delta, // h2 = Δ_i = pk_D^skE
                skE // witness x = skE
        );

        return new DecryptionShare(A_i, proof);
    }
}
