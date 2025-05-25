package org.example.pvss.dto;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

public class ThresholdKeyOutputDTO {
    public String id;
    public int dealerIndex;
    public int partyIndex;
    public String tauPkiHex;
    public DleqProofDTO proof;

    public ThresholdKeyOutputDTO() {

    }

    public ThresholdKeyOutputDTO(
            int dealerIndex,
            int partyIndex,
            ECPoint tauPki,
            BigInteger challenge,
            BigInteger response) {

        this.dealerIndex = dealerIndex;
        this.partyIndex = partyIndex;
        this.tauPkiHex = org.example.pvss.NapDkgParty.encodePoint(tauPki);
        // assume DleqProofDTO has a constructor taking raw BigIntegers
        this.proof = new DleqProofDTO(challenge, response);
    }
}
