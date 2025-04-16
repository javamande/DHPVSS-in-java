package org.example.pvss;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Represents the context (public parameters) for DHPVSS as defined in the
 * paper:
 *
 * pp = (G, G, p, t, n, α₀, {(αᵢ, vᵢ) : i ∈ [n]})
 *
 * 
 * /**
 */

public class DhPvssContext {
    private final GroupGenerator.GroupParameters groupParams;
    private final int t; // threshold
    private final int n; // number of participants
    private final BigInteger[] alphas; // evaluation points (e.g., [0, 1, 2, …, n])
    private final BigInteger[] v; // dual-code coefficients (if used)

    public DhPvssContext(GroupGenerator.GroupParameters groupParams, int t, int n, BigInteger[] alphas,
            BigInteger[] v) {
        this.groupParams = groupParams;
        this.t = t;
        this.n = n;
        this.alphas = alphas;
        this.v = v;
    }

    public BigInteger getOrder() {
        // We might need p from the underlying field for certain computations.
        return groupParams.getgroupOrd();
    }

    public ECPoint getGenerator() {
        return groupParams.getG();
    }

    public int getThreshold() {
        return t;
    }

    public int getNumParticipants() {
        return n;
    }

    public BigInteger[] getAlphas() {
        return alphas;
    }

    public BigInteger[] getV() {
        return v;
    }

    public GroupGenerator.GroupParameters getGroupParameters() {
        return groupParams;
    }
}
