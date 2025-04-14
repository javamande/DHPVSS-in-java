package org.example.pvss;

import org.bouncycastle.math.ec.ECPoint;

public class DistributionInput {
    private final DhKeyPair dealerKeyPair;
    private final EphemeralKeyPublic[] ephemeralKeys; // Only public parts (and proofs)
    private final ECPoint secret;

    public DistributionInput(DhKeyPair dealerKeyPair, EphemeralKeyPublic[] ephemeralKeys, ECPoint secret) {
        this.dealerKeyPair = dealerKeyPair;
        this.ephemeralKeys = ephemeralKeys;
        this.secret = secret;
    }

    public DhKeyPair getDealerKeyPair() {
        return dealerKeyPair;
    }

    /**
     * Returns the array of ephemeral key objects. Use getPublicKey() to access each
     * ECPoint.
     */
    public EphemeralKeyPublic[] getEphemeralKeys() {
        return ephemeralKeys;
    }

    public ECPoint getSecret() {
        return secret;
    }
}
