// src/main/java/org/example/pvss/dto/DleqProofDTO.java
package org.example.napdkg.dto;

import java.math.BigInteger;

import org.example.napdkg.core.NizkDlEqProof;

public class DleqProofDTO {
    public final String challenge; // hex or decimal
    public final String response;

    public DleqProofDTO(BigInteger e, BigInteger z) {
        this.challenge = e.toString(16);
        this.response = z.toString(16);
    }

    public String getChallenge() {
        return challenge;
    }

    public String getResponse() {
        return response;
    }

    public NizkDlEqProof toProof() {
        // parse the stored hex‐strings back into BigIntegers
        BigInteger eBI = new BigInteger(this.challenge, 16);
        BigInteger zBI = new BigInteger(this.response, 16);
        return new NizkDlEqProof(eBI, zBI);
    }
}
