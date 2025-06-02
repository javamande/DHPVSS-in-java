
package org.example.napdkg.core;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

public class Share {
    private final BigInteger a; // the scalar share
    private final ECPoint A; // the ECPoint = G·a

    public Share(BigInteger a, ECPoint A) {
        this.a = a;
        this.A = A;
    }

    public BigInteger getai() {
        return a;
    }

    public ECPoint getAiPoint() {
        return A;
    }

}