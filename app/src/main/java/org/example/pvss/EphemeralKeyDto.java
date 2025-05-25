package org.example.pvss;

public class EphemeralKeyDto {
    // Base64–encoded compressed ECPoint
    public final String E;
    // “e:z” as a single string
    public final NizkDlProof proof;

    public EphemeralKeyDto(EphemeralKeyPublic in) {
        this.E = in.getPublicKey().toString(); // or in.getPublicKey().getEncoded(true)
        this.proof = in.getProof();
    }
}
