package org.example.napdkg.dto;

import org.bouncycastle.util.encoders.Hex;
import org.example.napdkg.core.SharingOutput;

public class SharingOutputDTO {
    // make id non-final, provide a no-arg ctor
    public String id;
    public int dealerIndexDTO, publisherindexDTO;
    public String dealerPub; // hex
    public String[] Cij; // hex[]
    public String[] CHat; // hex[]
    public DleqProofDTO proof;

    // needed so Gson can do `new SharingOutputDTO()` and then set fields by
    // reflection
    public SharingOutputDTO() {
    }

    // used when *publishing* — note: do not set id here
    private SharingOutputDTO(SharingOutput in) {
        this.dealerIndexDTO = in.dealerIndex;
        this.publisherindexDTO = in.publisherIndex;
        this.dealerPub = Hex.toHexString(in.dealerPub.normalize().getEncoded(true));
        this.Cij = new String[in.Cij.length];
        this.CHat = new String[in.CHat.length];
        for (int i = 0; i < in.Cij.length; i++)
            this.Cij[i] = Hex.toHexString(in.Cij[i].normalize().getEncoded(true));
        for (int i = 0; i < in.CHat.length; i++)
            this.CHat[i] = in.CHat[i].toString(16);
        this.proof = new DleqProofDTO(
                in.proof.getChallenge(),
                in.proof.getResponse());
    }

    public DleqProofDTO getProof() {
        return proof;
    }

    public static class ProofDTO {
        public String challengeHex;
        public String responseHex;
    }

    public static SharingOutputDTO from(SharingOutput in) {
        return new SharingOutputDTO(in);
    }
}
