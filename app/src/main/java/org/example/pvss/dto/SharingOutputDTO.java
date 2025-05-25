package org.example.pvss.dto;

import org.bouncycastle.util.encoders.Hex;
import org.example.pvss.NapDkgParty.SharingOutput;

public class SharingOutputDTO {
    // make id non-final, provide a no-arg ctor
    public String id;
    public int dealerIndex;
    public String dealerPub; // hex
    public String[] Cij; // hex[]
    public String[] CHat; // hex[]
    public DleqProofDTO proof;

    // needed so Gson can do `new SharingOutputDTO()` and then set fields by
    // reflection
    public SharingOutputDTO() {
    }

    // used when *publishing* — note: do not set id here
    public SharingOutputDTO(SharingOutput in) {

        this.dealerIndex = in.dealerIndex;
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
}
