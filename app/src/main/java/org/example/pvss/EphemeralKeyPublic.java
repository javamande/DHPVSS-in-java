package org.example.pvss;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Container for an ephemeral public key along with its proof.
 * This class encapsulates the public part of an ephemeral key
 * (E) and a proof object (e.g. a NIZK proof) that the key is well‐formed.
 */
public class EphemeralKeyPublic {
    private final ECPoint ephemeralPublicKey;
    private final NizkDlProof proof; // This may be null if a proof is not generated

    public EphemeralKeyPublic(ECPoint ephemeralPublicKey, NizkDlProof proof) {
        this.ephemeralPublicKey = ephemeralPublicKey;
        this.proof = proof;
    }

    /**
     * Returns the ephemeral public key.
     */
    public ECPoint getPublicKey() {
        return ephemeralPublicKey;
    }

    /**
     * Returns the NIZK proof associated with this ephemeral key.
     */
    public NizkDlProof getProof() {
        return proof;
    }

    @Override
    public String toString() {
        return "EphemeralKeyPublic { ephemeralPublicKey=" + ephemeralPublicKey + ", proof=" + proof + " }";
    }
}
