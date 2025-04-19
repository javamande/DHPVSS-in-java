package org.example.pvss;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;

/**
 * A Diffie–Hellman key pair over the elliptic‑curve group 𝔾 of prime order p.
 * 
 * sk ∈ ℤ_p – the secret scalar
 * pk = sk · G – the public EC point, where G is the fixed group generator
 */
public class DhKeyPair {
    // the secret key sk, a value in the field ℤ_p
    private final BigInteger secretKey;
    // the public key PK = sk·G, an ECPoint on the curve
    private final ECPoint pub;

    /**
     * Constructs a new key pair.
     *
     * @param secretKey the secret scalar sk ∈ ℤ_p
     * @param pub       the public point PK = sk·G in 𝔾
     */
    public DhKeyPair(BigInteger secretKey, ECPoint pub) {
        this.secretKey = secretKey;
        this.pub = pub;
    }

    /**
     * @return the secret scalar sk
     */
    public BigInteger getSecretKey() {
        return secretKey;
    }

    /**
     * @return the public key point PK = sk·G
     */
    public ECPoint getPublic() {
        return pub;
    }

    /**
     * Generates a fresh key pair for the DHPVSS protocol.
     *
     * Picks sk uniformly at random from [1, p−1], where p is the prime order
     * of the elliptic‑curve group 𝔾, then computes PK = sk·G.
     *
     * @param ctx the PVSS context containing 𝔾, its order p, and generator G
     * @return a new DhKeyPair(sk, PK)
     */
    public static DhKeyPair generate(DhPvssContext ctx) {
        SecureRandom random = new SecureRandom();

        // p = order of the curve group 𝔾
        BigInteger p = ctx.getGroupParameters().getgroupOrd();
        // G = fixed generator point in 𝔾
        ECPoint G = ctx.getGenerator();

        // pick sk ∈ {1,...,p−1}
        BigInteger sk;
        do {
            sk = new BigInteger(p.bitLength(), random);
        } while (sk.compareTo(BigInteger.ONE) < 0
                || sk.compareTo(p) >= 0);

        // PK = sk · G
        ECPoint PK = G.multiply(sk).normalize();

        return new DhKeyPair(sk, PK);
    }
}
