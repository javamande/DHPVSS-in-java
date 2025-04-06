package org.example.pvss;

import org.bouncycastle.math.ec.ECPoint;

public final class ParticipantKeyData {
    private final ECPoint publicKey;
    private final NizkDlProof proof;

    public ParticipantKeyData(ECPoint publicKey, NizkDlProof proof) {
        this.publicKey = publicKey;
        this.proof = proof;
    }

    public ECPoint getPublicKey() {
        return publicKey;
    }

    public NizkDlProof getProof() {
        return proof;
    }

    @Override
    public String toString() {
        return "ParticipantKeyData{" +
                "publicKey=" + publicKey +
                ", proof=" + proof +
                '}';
    }
}
