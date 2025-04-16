// In DHPVSS_Decryption.java
package org.example.pvss;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

public class DhPvss_Decryption {

    public static class DecryptionShare {
        private final ECPoint share; // A_i
        private final NizkDlEqProof proof; // proof that log_G(E_i)==log_pkD(Δ_i)

        public DecryptionShare(ECPoint share, NizkDlEqProof proof) {
            this.share = share;
            this.proof = proof;
        }

        public ECPoint getShare() {
            return share;
        }

        public NizkDlEqProof getProof() {
            return proof;
        }
    }

    /**
     * Given the dealer public key pkD = G·skD, ephemeral public key E_i = G·skE,
     * the corresponding secret skE, and the encrypted share C_i = A_i + skD·E_i,
     * recover A_i and prove correctness:
     *
     * @param ctx PVSS context
     * @param pkD dealer public key
     * @param E_i participant ephemeral public key
     * @param skE that participant's ephemeral secret
     * @param C_i encrypted share
     */
    public static DecryptionShare decShare(
            DhPvssContext ctx,
            ECPoint pkD,
            ECPoint E_i,
            BigInteger skE,
            ECPoint C_i) {
        // 1) Recover share: A_i = C_i - skE·pkD
        ECPoint delta = pkD.multiply(skE).normalize();
        ECPoint A_i = C_i.subtract(delta).normalize();

        // 2) Prove DLEQ: show ∃x=skE such that
        // E_i = G^x and delta = pkD^x
        // Use your existing DLEQ‐proof routine:
        NizkDlEqProof proof = NizkDlEqProof.generateProof(
                ctx,
                pkD, // base2 = pkD
                E_i, // h1 = E_i = G^skE
                delta, // h2 = delta = pkD^skE
                skE // witness
        );

        return new DecryptionShare(A_i, proof);
    }
}
