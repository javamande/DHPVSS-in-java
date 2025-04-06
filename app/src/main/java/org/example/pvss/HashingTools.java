package org.example.pvss;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashingTools {
    private static final String HASH_ALGORITHM = "SHA-256";
    private static final byte SENTINEL = (byte) 0xac;

    /**
     * Returns a new MessageDigest instance for SHA-256.
     */
    public static MessageDigest getDigest() {
        try {
            return MessageDigest.getInstance(HASH_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * Updates the provided MessageDigest with the byte representation of the
     * BigInteger,
     * followed by a sentinel byte.
     *
     * @param digest the MessageDigest to update
     * @param bn     the BigInteger to hash
     */
    public static void updateDigestWithBigInteger(MessageDigest digest, BigInteger bn) {
        // Get the byte representation of bn.
        byte[] bnBytes = bn.toByteArray();
        // Update digest with bn bytes.
        digest.update(bnBytes);
        // Append a sentinel byte to detect boundary issues.
        digest.update(new byte[] { SENTINEL });
    }

    public static BigInteger[] hashPointsToPoly(BigInteger dealerPub,
            BigInteger[] comKeys,
            BigInteger[] encryptedShares,
            int numPolyCoeffs,
            BigInteger modulus) {
        // List 1: a singleton [dealerPub]
        BigInteger listDigest1 = hashBigIntegers(dealerPub);
        // List 2: hash over the array comKeys
        BigInteger listDigest2 = hashBigIntegers(comKeys);
        // List 3: hash over the array encryptedShares
        BigInteger listDigest3 = hashBigIntegers(encryptedShares);

        // Combine the three digests by hashing them together.
        BigInteger initialCoeff = hashBigIntegers(listDigest1, listDigest2, listDigest3).mod(modulus);

        BigInteger[] polyCoeffs = new BigInteger[numPolyCoeffs];
        polyCoeffs[0] = initialCoeff;

        // Build a hash chain for the remaining coefficients.
        for (int i = 1; i < numPolyCoeffs; i++) {
            polyCoeffs[i] = hashBigInteger(polyCoeffs[i - 1]).mod(modulus);
        }

        return polyCoeffs;
    }

    /**
     * Computes a SHA-256 hash over the BigInteger.
     *
     * @param bn the BigInteger to hash
     * @return the resulting hash as a positive BigInteger
     */
    public static BigInteger hashBigInteger(BigInteger bn) {
        MessageDigest digest = getDigest();
        updateDigestWithBigInteger(digest, bn);
        byte[] hash = digest.digest();
        return new BigInteger(1, hash);
    }

    /**
     * Computes a SHA-256 hash over multiple BigIntegers.
     *
     * @param bns an array of BigIntegers to hash
     * @return the resulting hash as a positive BigInteger
     */
    public static BigInteger hashBigIntegers(BigInteger... bns) {
        MessageDigest digest = getDigest();
        for (BigInteger bn : bns) {
            updateDigestWithBigInteger(digest, bn);
        }
        byte[] hash = digest.digest();
        return new BigInteger(1, hash);
    }

    /**
     * Computes a SHA-256 hash over the provided byte array.
     *
     * @param data the data to hash
     * @return the resulting hash as a positive BigInteger
     */
    public static BigInteger hashBytes(byte[] data) {
        MessageDigest digest = getDigest();
        digest.update(data);
        byte[] hash = digest.digest();
        return new BigInteger(1, hash);
    }
}
