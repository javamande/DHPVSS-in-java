package org.example.pvss;

import java.math.BigInteger;
import java.security.SecureRandom;

public class DhKeyPair {
    private final BigInteger secretKey;
    private final BigInteger pub;

    public DhKeyPair(BigInteger secretKey, BigInteger pub) {
        this.secretKey = secretKey;
        this.pub = pub;
    }

    public BigInteger getSecretKey() {
        return secretKey;
    }

    public BigInteger getPublic() {
        return pub;
    }

    /**
     * Generates a keypair using the group parameters from the provided
     * DhPvssContext.
     * In a finite-field setting, the public key is computed as g^priv mod p.
     *
     * @param ctx    the DhPvssContext holding the group parameters.
     * @param random a source of randomness.
     * @return a new DhKeyPair.
     */
    public static DhKeyPair generate(DhPvssContext ctx, SecureRandom random) {
        BigInteger primeOrder = ctx.getOrder(); // the prime p
        BigInteger generator = ctx.getGenerator(); // the generator g
        // Assume the subgroup order is provided by the GroupParameters.
        // For example, in a safe prime setting, if p = 2q+1 then the subgroup order is
        // q.
        // Here, we'll assume your group parameters offer a getSubgroupOrder() method.
        BigInteger order = ctx.getGroupParameters().getSubgroupOrder();

        BigInteger secretKey;
        do {
            secretKey = new BigInteger(order.bitLength(), random);
        } while (secretKey.compareTo(BigInteger.ZERO) == 0 || secretKey.compareTo(order) >= 0);

        // Compute the public key: pub = generator^priv mod modulus.
        BigInteger pub = generator.modPow(secretKey, primeOrder);

        return new DhKeyPair(secretKey, pub);
    }
}
