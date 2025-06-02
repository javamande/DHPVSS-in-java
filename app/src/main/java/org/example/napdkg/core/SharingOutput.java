// src/main/java/org/example/napdkg/core/domain/SharingOutput.java
package org.example.napdkg.core;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.example.napdkg.dto.SharingOutputDTO;
import org.example.napdkg.util.DkgContext;

public class SharingOutput {
    public final int dealerIndex;
    public final int publisherIndex;

    public final ECPoint dealerPub;
    public final ECPoint[] Cij;
    public final BigInteger[] CHat;
    public final NizkDlEqProof proof;

    public SharingOutput(int dealerIndex,
            int publisherIndex,
            ECPoint dealerPub,
            ECPoint[] Cij,
            BigInteger[] CHat,
            NizkDlEqProof proof) {
        this.dealerIndex = dealerIndex;
        this.publisherIndex = publisherIndex;
        this.dealerPub = dealerPub;
        this.Cij = Cij;
        this.CHat = CHat;
        this.proof = proof;
    }

    public int getDealerIndex() {
        return dealerIndex;
    }

    public ECPoint getDealerPub() {
        return dealerPub;
    }

    public ECPoint[] getCij() {
        return Cij;
    }

    public BigInteger[] getCHat() {
        return CHat;
    }

    public NizkDlEqProof getProof() {
        return proof;
    }

    /**
     * Convert from the wire‐DTO into your domain object
     */
    public static SharingOutput fromDTO(SharingOutputDTO dto, DkgContext ctx) {
        // 1) dealer’s public point
        ECPoint dealerPub = ctx.getGenerator()
                .getCurve()
                .decodePoint(Hex.decode(dto.dealerPub))
                .normalize();

        // 2) encrypted shares C_{j,1…n}
        ECPoint[] Cij = new ECPoint[dto.Cij.length];
        for (int i = 0; i < Cij.length; i++) {
            byte[] raw = Hex.decode(dto.Cij[i]);
            Cij[i] = ctx.getGenerator()
                    .getCurve()
                    .decodePoint(raw)
                    .normalize();
        }

        // 3) mask proofs Ŝ_{j,1…n}
        BigInteger[] CHat = new BigInteger[dto.CHat.length];
        for (int i = 0; i < CHat.length; i++) {
            CHat[i] = new BigInteger(dto.CHat[i], 16);
        }
        // reconstruct the DLEQ proof from the actual DTO fields:
        BigInteger e = new BigInteger(dto.proof.getChallenge(), 16);
        BigInteger z = new BigInteger(dto.proof.getResponse(), 16);
        NizkDlEqProof proof = new NizkDlEqProof(e, z);
        // 4) DLEQ proof

        return new SharingOutput(
                dto.dealerIndexDTO,
                dto.publisherindexDTO,
                dealerPub,
                Cij,
                CHat,
                proof);
    }

}
