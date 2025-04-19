package org.example.pvss;

/**
 * Binds a participant identifier to its DH key pair and a Schnorr‐style DL
 * proof.
 */
public class ParticipantKeyPair {
    private final String id;
    private final DhKeyPair keyPair;
    private final NizkDlProof proof;

    /**
     * @param id      unique participant identifier
     * @param keyPair Diffie–Hellman key pair
     * @param proof   NIZK proof of knowledge of the keyPair’s secret
     */
    public ParticipantKeyPair(String id, DhKeyPair keyPair, NizkDlProof proof) {
        this.id = id;
        this.keyPair = keyPair;
        this.proof = proof;
    }

    /** Participant’s identifier. */
    public String getId() {
        return id;
    }

    /** Returns the DH key pair. */
    public DhKeyPair getKeyPair() {
        return keyPair;
    }

    /** Returns the Schnorr‐style proof for that key. */
    public NizkDlProof getProof() {
        return proof;
    }

    @Override
    public String toString() {
        return "ParticipantKeyPair{" +
                "id='" + id + '\'' +
                ", keyPair=" + keyPair +
                ", proof=" + proof +
                '}';
    }
}
