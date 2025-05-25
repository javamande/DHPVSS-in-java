package org.example.pvss.dto;

public class EphemeralKeyDTO {
  public String id;
  public int partyIndex;
  public String publicKey; // hex-encoded ECPoint
  public String schnorrProof; // hex-encoded challenge ∥ response

  // empty no‐arg ctor for Gson
  public EphemeralKeyDTO() {
  }

  // convenience ctor
  public EphemeralKeyDTO(String id, int partyIndex, String publicKey, String schnorrProof) {
    this.id = id;
    this.partyIndex = partyIndex;
    this.publicKey = publicKey;
    this.schnorrProof = schnorrProof;
  }
}
