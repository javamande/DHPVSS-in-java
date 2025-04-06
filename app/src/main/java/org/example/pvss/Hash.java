package org.example.pvss;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hash {
    /**
     * Hashes the elements g, pub, and commitment A into a BigInteger.
     * In this finite-field setting, we simply convert the BigIntegers to byte
     * arrays.
     *
     * @param group      the group parameters containing g and p.
     * @param pub        the public key (g^x mod p).
     * @param commitment the commitment (g^r mod p).
     * @return a positive BigInteger derived from hashing the inputs.
     *         //
     */
    // * @return a BigInteger representing the challenge (before reduction modulo
    // the
    // * group order)
    // * Each participant generates a secret key 𝑤 and computes their public
    // * key as 𝑋=𝐺^𝑤 .
    // * The DL proof shows that the participant truly knows 𝑤 corresponding
    // * to the public key 𝑋.
    // * This prevents someone from publishing a bogus public key (i.e., one
    // * not derived from a known secret), which is essential for the overall
    // * security of the protocol.
    // */

    // Helper: convert a byte array to a hexadecimal string.
    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] toFixedLength(BigInteger n, int length) {
        byte[] raw = n.toByteArray();
        if (raw.length == length) {
            return raw;
        } else if (raw.length > length) {
            // Possibly raw contains a leading zero; trim it.
            byte[] trimmed = new byte[length];
            System.arraycopy(raw, raw.length - length, trimmed, 0, length);
            return trimmed;
        } else {
            byte[] padded = new byte[length];
            System.arraycopy(raw, 0, padded, length - raw.length, raw.length);
            return padded;
        }
    }

    public static BigInteger hashElements(DhPvssContext ctx, BigInteger pub, BigInteger commitment) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            int len = (ctx.getOrder().bitLength() + 7) / 8;
            byte[] gBytes = toFixedLength(ctx.getGenerator(), len);
            byte[] pubBytes = toFixedLength(pub, len);
            byte[] commitBytes = toFixedLength(commitment, len);

            // Minimal debug prints:
            System.out.println("DEBUG: Generator (g) hex: " + toHex(gBytes));
            System.out.println("DEBUG: Public key hex: " + toHex(pubBytes));
            System.out.println("DEBUG: Commitment hex: " + toHex(commitBytes));

            digest.update(gBytes);
            digest.update(pubBytes);
            digest.update(commitBytes);
            byte[] hash = digest.digest();
            BigInteger hashBI = new BigInteger(1, hash);
            System.out.println("DEBUG: Raw hash: " + hashBI.toString(16));
            return hashBI;
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("SHA-256 algorithm not available", ex);
        }
    }

    /**
     * Overloaded method that hashes the elements g, x, h, y, a1, and a2 into a
     * BigInteger.
     * This method is used in the DLEQ proof.
     *
     * @param ctx the PVSS context (for group parameters)
     * @param x   the value g^α mod p
     * @param h   the second base
     * @param y   the value h^α mod p
     * @param a1  the first commitment (g^w mod p)
     * @param a2  the second commitment (h^w mod p)
     * @return a positive BigInteger derived from hashing the inputs.
     */
    public static BigInteger hashElements(DhPvssContext ctx,
            BigInteger x,
            BigInteger h,
            BigInteger y,
            BigInteger a1,
            BigInteger a2) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            int len = (ctx.getOrder().bitLength() + 7) / 8;
            digest.update(toFixedLength(ctx.getGenerator(), len));
            digest.update(toFixedLength(x, len));
            digest.update(toFixedLength(h, len));
            digest.update(toFixedLength(y, len));
            digest.update(toFixedLength(a1, len));
            digest.update(toFixedLength(a2, len));
            byte[] hash = digest.digest();
            return new BigInteger(1, hash);
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("SHA-256 algorithm not available", ex);
        }
    }
}
