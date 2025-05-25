package org.example.pvss.dto;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

public class ShareVerificationOutputDTO {
    public String id;
    public int dealerIndex;
    public int verifierIndex;
    public String shareHex;
    public String[] CijHex;

    public ShareVerificationOutputDTO() {
    }

    public ShareVerificationOutputDTO(
            int dealerIndex,
            int verifierIndex,
            BigInteger share,
            ECPoint[] Cij) {
        this.dealerIndex = dealerIndex;
        this.verifierIndex = verifierIndex;
        // share is already a java.math.BigInteger
        this.shareHex = org.example.pvss.NapDkgParty.encodeScalar(share);

        this.CijHex = new String[Cij.length];
        for (int i = 0; i < Cij.length; i++) {
            this.CijHex[i] = org.example.pvss.NapDkgParty.encodePoint(Cij[i]);
        }
    }
}
