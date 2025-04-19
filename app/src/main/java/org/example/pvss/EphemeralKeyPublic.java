package org.example.pvss;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Represents the ephemeral role key E_i in DHPVSS
 * - E_i ∈ 𝔾 is the public key for role i, computed as E_i = G · skE_i.
 * - Accompanied by a NIZK proof π proving knowledge of skE_i such that
 * log_G(E_i) = skE_i
 * (i.e. proof that E_i is well‑formed).
 */
public class EphemeralKeyPublic {
    private final ECPoint E; // Role i’s public key E_i
    private final NizkDlProof proof; // π: NIZK proof of DLOG_G(E_i)

    public EphemeralKeyPublic(ECPoint E, NizkDlProof proof) {
        this.E = E;
        this.proof = proof;
    }

    /**
     * Returns the ephemeral committee key E_i ∈ 𝔾.
     */
    public ECPoint getPublicKey() {
        return E;
    }

    /**
     * Returns the non‑interactive proof π that shows E_i = G · skE_i.
     */
    public NizkDlProof getProof() {
        return proof;
    }

    @Override
    public String toString() {
        return "EphemeralKeyPublic { E=" + E + ", π=" + proof + " }";
    }
}
