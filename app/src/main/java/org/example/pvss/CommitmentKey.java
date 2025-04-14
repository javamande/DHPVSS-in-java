package org.example.pvss;

import org.bouncycastle.math.ec.ECPoint;

public class CommitmentKey {
    private final ECPoint ephemeralPublicKey; // Represents Ei.
    private final NizkDlProof proof; // Or your specific proof class, if available.

    public CommitmentKey(ECPoint ephemeralPublicKey, NizkDlProof proof) {
        this.ephemeralPublicKey = ephemeralPublicKey;
        this.proof = proof;
    }

    public ECPoint getEphemeralPublicKey() {
        return ephemeralPublicKey;
    }

    public NizkDlProof getProof() {
        return proof;
    }

    @Override
    public String toString() {
        return "CommitmentKey{ephemeralPublicKey=" + ephemeralPublicKey + ", proof=" + proof + "}";
    }
}
