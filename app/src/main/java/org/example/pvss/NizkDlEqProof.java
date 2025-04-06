package org.example.pvss;

import java.math.BigInteger;

public class NizkDlEqProof {
    private final BigInteger challenge;
    private final BigInteger response;

    public NizkDlEqProof(BigInteger challenge, BigInteger response) {
        this.challenge = challenge;
        this.response = response;
    }

    public BigInteger getChallenge() {
        return challenge;
    }

    public BigInteger getResponse() {
        return response;
    }

    @Override
    public String toString() {
        return "DleqProof{" +
                "challenge=" + challenge +
                ", response=" + response +
                '}';
    }
}
