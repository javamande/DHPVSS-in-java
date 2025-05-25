package org.example.pvss;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.math.ec.ECPoint;

public class HashingTools {

    /**
     * Hashes a single group element P ∈ 𝔾 to Zₚ via SHA‑256.
     *
     * @param point the ECPoint P in the elliptic‐curve group 𝔾
     * @return H(P) interpreted as a nonnegative BigInteger (i.e. ∈ Zₚ)
     */
    public static BigInteger hashECPoint(ECPoint point) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encoded = point.getEncoded(true); // compressed form
            digest.update(encoded);
            byte[] hashBytes = digest.digest();
            return new BigInteger(1, hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    public static byte[] hashECPointToBytes(ECPoint point) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encoded = point.getEncoded(true); // compressed form
            digest.update(encoded);
            byte[] hashBytes = digest.digest();
            return hashBytes;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * Hashes a sequence of group elements [P₁…P_k]∈𝔾 by concatenating their
     * compressed encodings, then SHA‑256.
     *
     * @param points the ECPoints P₁…P_k
     * @return H(P₁ ∥ … ∥ P_k) as a nonnegative BigInteger
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
     * Builds a pseudo‐random polynomial m*(X) ∈ Zₚ[X] for the SCRAPE dual‐code
     * test.
     *
     * 1. d₀ ← H( pk_D ∥ E₁ ∥ … ∥ E_n ∥ C₁ ∥ … ∥ C_n )
     * 2. dᵢ ← H(dᵢ₋₁) for i = 1…numPolyCoeffs−1
     * 
     * These coefficients feed into the SCRAPE check via evaluations at αᵢ.
     *
     * @param dealerPub       dealer’s EC public key pk_D
     * @param comKeys         array of ephemeral keys Eᵢ
     * @param encryptedShares array of encrypted shares Cᵢ
     * @param numPolyCoeffs   number of coefficients to output (degree+1)
     * @param modulus         the prime p = |𝔾| for reduction
     * @return [d₀…d_{numPolyCoeffs−1}] ∈ Zₚ^{numPolyCoeffs}
     */
    public static BigInteger[] hashPointsToPoly(ECPoint dealerPub,
            ECPoint[] comKeys,
            ECPoint[] encryptedShares,
            int numPolyCoeffs,
            BigInteger modulus, DhPvssContext ctx) {
        // 1) seed ← H(pk_D ∥ E₁…E_n ∥ C₁…C_n) mod p
        BigInteger listDigest1 = hashECPoint(dealerPub);
        BigInteger listDigest2 = hashECPoints(comKeys);
        BigInteger listDigest3 = hashECPoints(encryptedShares);

        // 2) initial coefficient
        BigInteger initialCoeff = hashBigIntegers(ctx, listDigest1, listDigest2, listDigest3)
                .mod(modulus);

        // 3) extend by hashing previous
        BigInteger[] polyCoeffs = new BigInteger[numPolyCoeffs];
        polyCoeffs[0] = initialCoeff;
        for (int i = 1; i < numPolyCoeffs; i++) {
            polyCoeffs[i] = hashBigIntegers(ctx, polyCoeffs[i - 1]).mod(modulus);
        }
        return polyCoeffs;
    }

    /**
     * Compressed ECPoint → byte[] helper.
     */
    private static byte[] encodeECPoint(ECPoint point) {
        return point.getEncoded(true);
    }

    /**
     * Pads or trims a BigInteger’s byte[] to exactly length bytes.
     *
     * @param n      the BigInteger to encode
     * @param length desired output length
     * @return fixed‐length big‐endian byte array
     */
    private static byte[] toFixedLength(BigInteger n, int length) {
        byte[] raw = n.toByteArray();
        if (raw.length == length) {
            return raw;
        } else if (raw.length > length) {
            byte[] trimmed = new byte[length];
            System.arraycopy(raw, raw.length - length, trimmed, 0, length);
            return trimmed;
        } else {
            byte[] padded = new byte[length];
            System.arraycopy(raw, 0, padded, length - raw.length, raw.length);
            return padded;
        }
    }

    /**
     * Hashes fixed‐length encodings of field elements z₁…z_k ∈ Zₚ to Zₚ.
     *
     * Useful for chaining scalars into a single digest (e.g. polynomial seeds).
     *
     * @param bns the BigIntegers z₁…z_k
     * @return SHA-256(z₁ … z_k) as nonnegative BigInteger
     */
    public static BigInteger hashBigIntegers(DhPvssContext ctx, BigInteger... bns) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            // derive a uniform block size from the first input
            int len = (ctx.getOrder().bitLength() + 7) / 8;
            for (BigInteger bn : bns) {
                byte[] chunk = toFixedLength(bn, len);
                digest.update(chunk);
            }
            byte[] hash = digest.digest();
            return new BigInteger(1, hash);
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("SHA-256 algorithm not available", ex);
        }
    }

    /**
     * Hashes the six points (g, x, h, y, a1, a2) for the DLEQ proof χ.
     *
     * χ = SHA-256( compress(g) ∥ compress(x) ∥ compress(h)
     * ∥ compress(y) ∥ compress(a1) ∥ compress(a2) )
     *
     * @param ctx context for curve parameters
     * @param g   generator G
     * @param x   base public (e.g. pk_D)
     * @param h   second base (e.g. U)
     * @param y   second value (e.g. V)
     * @param a1  commitment g^w
     * @param a2  commitment h^w
     * @return χ as nonnegative BigInteger
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
            digest.update(encodeECPoint(g));
            digest.update(encodeECPoint(x));
            digest.update(encodeECPoint(h));
            digest.update(encodeECPoint(y));
            digest.update(encodeECPoint(a1));
            digest.update(encodeECPoint(a2));
            byte[] hash = digest.digest();

            // System.out.println("[hashElements] hash = " + Hex.toHexString(hash));

            return new BigInteger(1, hash);
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("SHA-256 algorithm not available", ex);
        }
    }

    /**
     * Overload: hash (g, pub, A) for a single‐base DL proof.
     *
     * SHA-256( compress(g) ∥ compress(pub) ∥ compress(A) )
     */
    public static BigInteger hashElements(DhPvssContext ctx,
            org.bouncycastle.math.ec.ECPoint pub,
            org.bouncycastle.math.ec.ECPoint A) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(encodeECPoint(ctx.getGenerator()));
            digest.update(encodeECPoint(pub));
            digest.update(encodeECPoint(A));
            byte[] hash = digest.digest();
            return new BigInteger(1, hash);
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("SHA-256 algorithm not available", ex);
        }
    }

    public static BigInteger[] deriveFirstRoundPoly(
            DhPvssContext ctx,
            ECPoint dealerPub, // pki = your E_i
            ECPoint[] comKeys, // E1…En
            ECPoint[] encryptedShares, // Ci,1…Ci,n
            BigInteger[] hatShares, // Ĉi,1…Ĉi,n
            int n,
            int t) {
        BigInteger p = ctx.getOrder();

        // 1) Hash the four chunks into a single seed ∈ Zp
        BigInteger h0 = hashECPoint(dealerPub);
        BigInteger h1 = hashECPoints(comKeys);
        BigInteger h2 = hashECPoints(encryptedShares);
        BigInteger h3 = hashBigIntegers(ctx, hatShares);
        // System.out.printf(" h0=%s%n h1=%s%n h2=%s%n h3=%s%n",
        // h0.toString(16), h1.toString(16), h2.toString(16), h3.toString(16));
        BigInteger seed = hashBigIntegers(ctx, h0, h1, h2, h3).mod(p);
        // System.out.println(" seed0=" + seed.toString(16));
        // 2) Number of coefficients = n - t
        int coeffs = n - t;
        BigInteger[] mStar = new BigInteger[coeffs];
        mStar[0] = BigInteger.ZERO;
        ;

        if (mStar.length > 1) {
            mStar[1] = seed; // seed = H( … ) mod p
            for (int i = 2; i < mStar.length; i++) {
                mStar[i] = hashBigIntegers(ctx, mStar[i - 1]).mod(p);
            }
        }
        return mStar;

    }
}
