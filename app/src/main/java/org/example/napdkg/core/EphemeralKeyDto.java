package org.example.napdkg.core;

public class EphemeralKeyDto {
    // Base64–encoded compressed ECPoint
    public final String E;
    // “e:z” as a single string
    public final NizkDlProof proof;

    public EphemeralKeyDto(PublicKeysWithProofs in) {
        this.E = in.getPublicKey().toString(); // or in.getPublicKey().getEncoded(true)
        this.proof = in.getProof();
    }
}
