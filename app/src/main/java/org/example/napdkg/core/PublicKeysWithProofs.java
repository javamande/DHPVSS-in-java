package org.example.napdkg.core;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Represents the ephemeral role key E_i in DHPVSS
 * - E_i ∈ 𝔾 is the public key for role i, computed as E_i = G · skE_i.
 * - Accompanied by a NIZK proof π proving knowledge of skE_i such that
 * log_G(E_i) = skE_i
 * (i.e. proof that E_i is well‑formed).
 */
public class PublicKeysWithProofs {
    private final int partyIndex;
    private final ECPoint publicKey;
    private final NizkDlProof proof;

    public PublicKeysWithProofs(int partyIndex,
            ECPoint publicKey,
            NizkDlProof proof) {
        this.partyIndex = partyIndex;
        this.publicKey = publicKey;
        this.proof = proof;
    }

    public int getPartyIndex() {
        return partyIndex;
    }

    public ECPoint getPublicKey() {
        return publicKey;
    }

    public NizkDlProof getProof() {
        return proof;
    }

    @Override
    public String toString() {
        return "EphemeralKeyPublic { E=" + publicKey + ", π=" + proof + " }";
    }
    // constructor, getters, etc.

    /**
     * Returns the uncompressed point encoding || challenge || response
     * all in a single byte array ready for hashing.
     */
}
