// src/main/java/org/example/pvss/dto/ThresholdKeyOutputDTO.java
package org.example.napdkg.dto;

import org.example.napdkg.core.ThresholdOutput;

public class ThresholdKeyOutputDTO {
    public String id;
    public int dealerIndex;
    public int partyIndex;
    public String tpkiHex;
    public DleqProofDTO proof;

    /** no-arg for Gson */
    public ThresholdKeyOutputDTO() {
    }

    /** private ctor used by our factory */
    private ThresholdKeyOutputDTO(ThresholdOutput in) {
        this.dealerIndex = in.dealerIndex;
        this.partyIndex = in.partyIndex;
        // encode the reconstructed public key point
        this.tpkiHex = org.example.napdkg.util.DkgUtils.encodePoint(in.tpki);
        // wrap its DLEQ proof
        this.proof = new DleqProofDTO(
                in.proof.getChallenge(),
                in.proof.getResponse());
    }

    /** factory for publishing */
    public static ThresholdKeyOutputDTO from(ThresholdOutput in) {
        return new ThresholdKeyOutputDTO(in);
    }
}
