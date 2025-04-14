package org.example.pvss;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;

public class DhKeyPair {
    // The dealer’s (or participant’s) secret key, a scalar in Z_n.
    private final BigInteger secretKey;
    // The corresponding public key, an EC point computed as G multiplied by the
    // secret.
    private final ECPoint pub;

    /**
     * Constructs a DhKeyPair with the provided secret and public key.
     *
     * @param secretKey the secret scalar in Z_n.
     * @param pub       the corresponding public key ECPoint.
     */
    public DhKeyPair(BigInteger secretKey, ECPoint pub) {
        this.secretKey = secretKey;
        this.pub = pub;
    }

    /**
     * Returns the secret key (a scalar in Z_n).
     *
     * @return the secret key.
     */
    public BigInteger getSecretKey() {
        return secretKey;
    }

    /**
     * Returns the public key as an ECPoint.
     *
     * @return the public key.
     */
    public ECPoint getPublic() {
        return pub;
    }

    /**
     * Generates a key pair using the elliptic curve group parameters contained in
     * the given PVSS context.
     * In elliptic curve cryptography, the secret key is a random scalar in Z_n, and
     * the public key is computed
     * as pub = G * secretKey, where G is the group generator.
     *
     * @param ctx    the PVSS context containing the EC group parameters.
     * @param random a source of secure randomness.
     * @return a new DhKeyPair with secret key and corresponding public key.
     */
    public static DhKeyPair generate(DhPvssContext ctx, SecureRandom random) {
        // Retrieve the subgroup order (n) from the context.
        // Note: For an EC group, this is the order of the generator (usually denoted by
        // N).
        BigInteger order = ctx.getGroupParameters().getN();
        // Retrieve the group generator (an ECPoint) from the context.
        ECPoint generator = ctx.getGenerator();

        // Generate a random secret key in the range [1, order - 1].
        BigInteger secretKey;
        do {
            secretKey = new BigInteger(order.bitLength(), random);
        } while (secretKey.compareTo(BigInteger.ZERO) <= 0 || secretKey.compareTo(order) >= 0);

        // Compute the public key as the scalar multiplication of the generator by the
        // secret key.
        // In elliptic curve cryptography, this is performed using the ECPoint multiply
        // method.
        ECPoint pub = generator.multiply(secretKey).normalize();

        return new DhKeyPair(secretKey, pub);
    }
}
