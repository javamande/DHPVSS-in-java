package org.example.pvss;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.math.ec.ECPoint;

public class HashingTools {

    /**
     * Hashes a single ECPoint using its compressed encoding.
     * 
     * @param point the ECPoint to hash
     * @return a BigInteger representing the hash (interpreted as positive)
     */
    public static BigInteger hashECPoint(ECPoint point) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encoded = point.getEncoded(true); // use compressed encoding
            digest.update(encoded);
            byte[] hashBytes = digest.digest();
            return new BigInteger(1, hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * Hashes an array of ECPoints by concatenating their compressed encodings.
     * 
     * @param points an array of ECPoints to hash
     * @return a BigInteger representing the hash of all points (interpreted as
     *         positive)
     */
    public static BigInteger hashECPoints(ECPoint... points) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (ECPoint point : points) {
                byte[] encoded = point.getEncoded(true);
                digest.update(encoded);
            }
            byte[] hashBytes = digest.digest();
            return new BigInteger(1, hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * Computes a hash-based polynomial from elliptic curve points.
     * 
     * This function takes as input:
     * <ul>
     * <li>the dealer’s public key (an ECPoint),</li>
     * <li>an array of commitment keys (ECPoints), and</li>
     * <li>an array of encrypted shares (ECPoints).</li>
     * </ul>
     * It then computes a hash digest for each group, combines them, and
     * “hash-chains” the result to produce
     * an array of coefficients (of length numPolyCoeffs) in Z_modulus.
     * 
     * @param dealerPub       the dealer’s public key as an ECPoint.
     * @param comKeys         the array of commitment keys (ECPoints).
     * @param encryptedShares the array of encrypted shares (ECPoints).
     * @param numPolyCoeffs   the number of polynomial coefficients to generate.
     * @param modulus         the modulus p (as a BigInteger) for reduction.
     * @return an array of BigInteger representing the polynomial coefficients.
     */
    public static BigInteger[] hashPointsToPoly(ECPoint dealerPub,
            ECPoint[] comKeys,
            ECPoint[] encryptedShares,
            int numPolyCoeffs,
            BigInteger modulus) {
        // Step 1: Compute a digest for each group.
        BigInteger listDigest1 = hashECPoint(dealerPub);
        BigInteger listDigest2 = hashECPoints(comKeys);
        BigInteger listDigest3 = hashECPoints(encryptedShares);

        // Step 2: Combine the digests by hashing them together.
        BigInteger initialCoeff = Hash.hashBigIntegers(listDigest1, listDigest2, listDigest3).mod(modulus);

        // Step 3: Build the hash chain for the remaining coefficients.
        BigInteger[] polyCoeffs = new BigInteger[numPolyCoeffs];
        polyCoeffs[0] = initialCoeff;
        for (int i = 1; i < numPolyCoeffs; i++) {
            polyCoeffs[i] = Hash.hashBigIntegers(polyCoeffs[i - 1]).mod(modulus);
        }
        return polyCoeffs;
    }

    // You already have hashBigInteger and hashBigIntegers methods defined elsewhere
    // in your code.
}
