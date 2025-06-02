package org.example.napdkg.core;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;
import org.example.napdkg.util.DkgContext;
import org.example.napdkg.util.HashingTools;

/**
 * A simple representation of a non-interactive zero-knowledge (NIZK) proof
 * for a discrete-logarithm relation on an elliptic curve.
 * It carries a challenge and a response.
 */
public class NizkDlProof {
    private final BigInteger challenge;
    private final BigInteger response;

    /**
     * @param challenge the Fiat–Shamir challenge e
     * @param response  the response z = r - e·x mod p
     */
    public NizkDlProof(BigInteger challenge, BigInteger response) {
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
        return "NizkDlProof{" +
                "challenge=" + challenge +
                ", response=" + response +
                '}';
    }

    private static final SecureRandom random = new SecureRandom();

    /**
     * Generates a NIZK proof of knowledge of x in pub = x·G via Fiat–Shamir:
     * 1) r ←R [1,p-1]
     * 2) A = r·G
     * 3) e = Hash(G,pub,A) mod p → seed PRG
     * 4) z = r - e·x mod p
     */
    public static NizkDlProof generateProof(DkgContext ctx, DhKeyPair keyPair)
            throws NoSuchAlgorithmException {
        BigInteger p = ctx.getOrder();
        ECPoint G = ctx.getGenerator();
        ECPoint pub = keyPair.getPublic();
        BigInteger x = keyPair.getSecretKey();

        BigInteger r;
        do {
            r = new BigInteger(p.bitLength(), random);
        } while (r.signum() <= 0 || r.compareTo(p) >= 0);

        ECPoint A = G.multiply(r);

        BigInteger seed = HashingTools.hashElements(ctx, pub, A).mod(p);
        SecureRandom prg = SecureRandom.getInstance("SHA1PRNG");
        prg.setSeed(seed.toByteArray());

        BigInteger e;
        do {
            e = new BigInteger(p.bitLength(), prg);
        } while (e.signum() <= 0 || e.compareTo(p) >= 0);

        BigInteger z = r.subtract(e.multiply(x)).mod(p);
        return new NizkDlProof(e, z);
    }

    /**
     * Verifies the NIZKDL proof:
     * A' = z·G + e·pub, then recompute e' = PRG( Hash(G,pub,A') )
     * and check e' == e.
     */
    public static boolean verifyProof(DkgContext ctx, ECPoint pub, NizkDlProof proof)
            throws NoSuchAlgorithmException {
        BigInteger p = ctx.getOrder();
        ECPoint G = ctx.getGenerator();
        BigInteger e = proof.getChallenge();
        BigInteger z = proof.getResponse();

        ECPoint Aprime = G.multiply(z).add(pub.multiply(e));
        BigInteger seed = HashingTools.hashElements(ctx, pub, Aprime).mod(p);
        SecureRandom prg = SecureRandom.getInstance("SHA1PRNG");
        prg.setSeed(seed.toByteArray());

        BigInteger e2;
        do {
            e2 = new BigInteger(p.bitLength(), prg);
        } while (e2.signum() <= 0 || e2.compareTo(p) >= 0);

        return e2.equals(e);
    }
}
