// src/main/java/org/example/pvss/dto/DleqProofDTO.java
package org.example.pvss.dto;

import java.math.BigInteger;

import org.example.pvss.NizkDlEqProof;

public class DleqProofDTO {
    public final String e; // hex or decimal
    public final String z;

    public DleqProofDTO(BigInteger e, BigInteger z) {
        this.e = e.toString(16);
        this.z = z.toString(16);
    }

    public NizkDlEqProof toProof() {
        // parse the stored hex‐strings back into BigIntegers
        BigInteger eBI = new BigInteger(this.e, 16);
        BigInteger zBI = new BigInteger(this.z, 16);
        return new NizkDlEqProof(eBI, zBI);
    }
}
