// src/main/java/org/example/pvss/dto/ShareVerificationOutputDTO.java
package org.example.napdkg.dto;

import org.bouncycastle.util.encoders.Hex;
import org.example.napdkg.core.ShareVerificationPublish;

public class ShareVerificationOutputDTO {
    public String id;
    public int verifierIndex;
    public String tauPki; // hex-encoded τ_{pk_i}
    public DleqProofDTO proof; // the final threshold DLEQ proof

    /** no-arg for Gson */
    public ShareVerificationOutputDTO() {
    }

    private ShareVerificationOutputDTO(ShareVerificationPublish in) {
        this.verifierIndex = in.verifierIndex;
        this.tauPki = Hex.toHexString(
                in.tpki
                        .normalize()
                        .getEncoded(false));
        this.proof = new DleqProofDTO(
                in.Pftpki.getChallenge(),
                in.Pftpki.getResponse());
    }

    /** factory for publishing */
    public static ShareVerificationOutputDTO from(ShareVerificationPublish in) {
        return new ShareVerificationOutputDTO(in);
    }
}
