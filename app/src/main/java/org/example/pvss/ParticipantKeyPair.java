package org.example.pvss;

public class ParticipantKeyPair {
    private final String id;
    private final DhKeyPair keyPair;
    private final NizkDlProof proof;

    public ParticipantKeyPair(String id, DhKeyPair keyPair, NizkDlProof proof) {
        this.id = id;
        this.keyPair = keyPair;
        this.proof = proof;
    }

    public String getId() {
        return id;
    }

    public DhKeyPair getKeyPair() {
        return keyPair;
    }

    public NizkDlProof getProof() {
        return proof;
    }

    // // Returns a lightweight tuple of public key and its associated DL proof.
    // public ParticipantKeyData asKeyData() {
    // return new ParticipantKeyData(keyPair.getPublic(), proof);
    // }

    @Override
    public String toString() {
        return "ParticipantKeyPair{" +
                "id='" + id + '\'' +
                ", keyPair=" + keyPair +
                ", proof=" + proof +
                '}';
    }
}
