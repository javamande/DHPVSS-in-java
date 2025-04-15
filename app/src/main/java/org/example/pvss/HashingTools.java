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
        BigInteger initialCoeff = hashBigIntegers(listDigest1, listDigest2, listDigest3).mod(modulus);

        // Step 3: Build the hash chain for the remaining coefficients.
        BigInteger[] polyCoeffs = new BigInteger[numPolyCoeffs];
        polyCoeffs[0] = initialCoeff;
        for (int i = 1; i < numPolyCoeffs; i++) {
            polyCoeffs[i] = hashBigIntegers(polyCoeffs[i - 1]).mod(modulus);
        }
        return polyCoeffs;
    }

    // * Returns the compressed encoding of an ECPoint as a fixed-length byte array.
    // *
    // * @param point the ECPoint to encode.
    // * @return the compressed encoding as a byte array.
    // */
    private static byte[] encodeECPoint(org.bouncycastle.math.ec.ECPoint point) {
        // Use compressed encoding; for secp256r1, the typical length is 33 bytes.
        return point.getEncoded(true);
    }

    /**
     * Converts the given BigInteger to a byte array of exactly the specified
     * length.
     * If the BigInteger's native byte array is shorter, it will be left-padded with
     * zeros;
     * if it is longer, only the least significant bytes are returned.
     *
     * @param n      the BigInteger to convert.
     * @param length the desired byte array length.
     * @return a byte array of the specified length.
     */
    private static byte[] toFixedLength(BigInteger n, int length) {
        byte[] raw = n.toByteArray();
        if (raw.length == length) {
            return raw;
        } else if (raw.length > length) {
            // Trim off any extra leading bytes (often a sign byte).
            byte[] trimmed = new byte[length];
            System.arraycopy(raw, raw.length - length, trimmed, 0, length);
            return trimmed;
        } else {
            // Pad with leading zeros.
            byte[] padded = new byte[length];
            System.arraycopy(raw, 0, padded, length - raw.length, raw.length);
            return padded;
        }
    }

    /**
     * Hashes the concatenation of the fixed-length byte representations of the
     * provided BigIntegers.
     * This is useful when you need to combine several scalar values into a single
     * hash (e.g. for
     * generating coefficients in a polynomial).
     *
     * @param bns the BigIntegers to
     * @return a positive BigInteger representing the SHA‑256 hash of the inputs.
     */
    public static BigInteger hashBigIntegers(BigInteger... bns) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            // Derive a fixed length from the first BigInteger (assumes all inputs are from
            // similar groups).
            int len = (bns[0].bitLength() + 7) / 8;
            for (BigInteger bn : bns) {
                byte[] bytes = toFixedLength(bn, len);
                digest.update(bytes);
            }
            byte[] hash = digest.digest();
            return new BigInteger(1, hash);
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("SHA-256 algorithm not available", ex);
        }
    }

    /**
     * Hashes the elements g, x, h, y, a1, and a2 into a BigInteger.
     * This method is used in the DLEQ proof to combine the fixed-length
     * representations of:
     * - g: the group generator,
     * - x: the public value (e.g., dealer’s public key, g^α),
     * - h: the second base (e.g., weighted aggregate U),
     * - y: the corresponding value (e.g., V),
     * - a1: the first commitment (g^w), and
     * - a2: the second commitment (h^w).
     *
     * @param ctx the PVSS context (for group parameters and fixed-length
     *            determination).
     * @param g   the group generator as an ECPoint.
     * @param x   the public value as an ECPoint.
     * @param h   the second base as an ECPoint.
     * @param y   the second public value as an ECPoint.
     * @param a1  the first commitment as an ECPoint.
     * @param a2  the second commitment as an ECPoint.
     * @return a positive BigInteger derived from the SHA‑256 hash of the
     *         concatenated encodings.
     */
    public static BigInteger hashElements(DhPvssContext ctx,
            org.bouncycastle.math.ec.ECPoint g,
            org.bouncycastle.math.ec.ECPoint x,
            org.bouncycastle.math.ec.ECPoint h,
            org.bouncycastle.math.ec.ECPoint y,
            org.bouncycastle.math.ec.ECPoint a1,
            org.bouncycastle.math.ec.ECPoint a2) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] gBytes = encodeECPoint(g);
            byte[] xBytes = encodeECPoint(x);
            byte[] hBytes = encodeECPoint(h);
            byte[] yBytes = encodeECPoint(y);
            byte[] a1Bytes = encodeECPoint(a1);
            byte[] a2Bytes = encodeECPoint(a2);

            digest.update(gBytes);
            digest.update(xBytes);
            digest.update(hBytes);
            digest.update(yBytes);
            digest.update(a1Bytes);
            digest.update(a2Bytes);
            byte[] hash = digest.digest();
            return new BigInteger(1, hash);
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("SHA-256 algorithm not available", ex);
        }
    }

    /**
     * Overloaded method to hash the elements g, pub, and commitment A into a
     * BigInteger.
     * This method is intended for use when you want to hash the group generator,
     * a public key, and a commitment (e.g., in generating a DL proof).
     *
     * @param ctx the PVSS context.
     * @param pub the public key as an ECPoint.
     * @param A   the commitment as an ECPoint.
     * @return a positive BigInteger derived from the SHA‑256 hash of the inputs.
     */
    public static BigInteger hashElements(DhPvssContext ctx, org.bouncycastle.math.ec.ECPoint pub,
            org.bouncycastle.math.ec.ECPoint A) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] gBytes = encodeECPoint(ctx.getGenerator());
            byte[] pubBytes = encodeECPoint(pub);
            byte[] ABytes = encodeECPoint(A);

            digest.update(gBytes);
            digest.update(pubBytes);
            digest.update(ABytes);
            byte[] hash = digest.digest();
            return new BigInteger(1, hash);
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("SHA-256 algorithm not available", ex);
        }
    }

}