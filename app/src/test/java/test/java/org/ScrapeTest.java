package test.java.org;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Minimal, self-contained multi-degree SCRAPE check for n=5, t=2.
 *
 * Steps:
 * 1) Uses the secp256k1 group order p = 0xFFFFFFFF FFFFFFFF ...
 * BFD25E8CD0364141 (hex).
 * 2) Builds a random polynomial of degree <= 2 (a0, a1, a2).
 * 3) alpha[i] = i, for i=1..5.
 * 4) Evaluates shares[i-1] = poly(alpha[i]).
 * 5) Derives v[i-1] = product_{j != i}(alpha[i] - alpha[j])^-1 mod p.
 * 6) For deg=0..(n-t-1)=2, checks sum_{i=1..5} v[i-1]*alpha[i]^deg*shares[i-1]
 * mod p == 0.
 *
 * Run:
 * javac ScrapeTest.java
 * java ScrapeTest
 */
public class ScrapeTest {

    // secp256k1 group order (hex):
    // FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
    // This is the prime "r" used for exponents in secp256k1, ~1.158e77.
    private static final String pHex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

    public static void main(String[] args) {
        // 1) Setup n=5, t=2
        int n = 5, t = 2;
        // p = secp256k1 group order
        BigInteger p = new BigInteger(pHex, 16);

        System.out.println("Using n=5, t=2, group order p=" + p.toString(16));

        // 2) Build a random polynomial a0 + a1*x + a2*x^2 (degree <= 2)
        BigInteger[] coeffs = new BigInteger[t + 1];
        for (int i = 0; i <= t; i++) {
            coeffs[i] = randomBig(p);
        }
        System.out.println("Polynomial coeffs (a0,a1,a2) mod p:");
        for (int i = 0; i <= t; i++) {
            System.out.println("  coeffs[" + i + "]=" + coeffs[i].toString(16));
        }

        // 3) alpha[i] = i, i=1..n
        // We'll store alpha in a 1-based array of length n+1
        BigInteger[] alpha = new BigInteger[n + 1];
        for (int i = 1; i <= n; i++) {
            alpha[i] = BigInteger.valueOf(i);
        }

        // 4) Evaluate shares[i-1] = poly(alpha[i])
        BigInteger[] shares = new BigInteger[n];
        for (int i = 1; i <= n; i++) {
            shares[i - 1] = evaluatePolynomial(coeffs, alpha[i], p);
        }

        // 5) Derive v-coeffs for i=1..n
        // v[i-1] = ( product_{j != i} (alpha[i] - alpha[j]) )^-1 mod p
        BigInteger[] v = deriveScrapeCoeffs(p, alpha, n);

        // 6) Multi-degree check up to deg = n - t - 1 = 2
        int maxDeg = n - t - 2;
        for (int d = 0; d <= maxDeg; d++) {
            BigInteger sum = BigInteger.ZERO;
            for (int i = 1; i <= n; i++) {
                BigInteger pow = alpha[i].modPow(BigInteger.valueOf(d), p);
                BigInteger term = v[i - 1].multiply(pow).mod(p)
                        .multiply(shares[i - 1]).mod(p);
                sum = sum.add(term).mod(p);
            }
            // Expect 0
            if (!sum.equals(BigInteger.ZERO)) {
                System.out.println("FAIL: deg=" + d + " => sum=" + sum.toString(16));
            } else {
                System.out.println("PASS: deg=" + d + " => sum=0");
            }
        }
    }

    /** Return a random BigInteger in [0..p-1]. */
    private static BigInteger randomBig(BigInteger p) {
        SecureRandom rnd = new SecureRandom();
        return new BigInteger(p.bitLength(), rnd).mod(p);
    }

    /** Evaluate polynomial coeffs[] at x, mod p (coeffs is a0..aD). */
    private static BigInteger evaluatePolynomial(BigInteger[] coeffs, BigInteger x, BigInteger p) {
        // Horner's method
        BigInteger result = BigInteger.ZERO;
        for (int i = coeffs.length - 1; i >= 0; i--) {
            result = result.multiply(x).add(coeffs[i]).mod(p);
        }
        return result;
    }

    /**
     * Derive Lagrange-like "dual code" coefficients v_i for i=1..n, given alpha[].
     * alpha is 1-based, alpha[i] distinct. Returns v[] of length n, v[i-1] =
     * product_{j != i}(alpha[i]-alpha[j])^-1 mod p.
     */
    private static BigInteger[] deriveScrapeCoeffs(BigInteger p, BigInteger[] alpha, int n) {
        BigInteger[] v = new BigInteger[n];
        for (int i = 1; i <= n; i++) {
            BigInteger num = BigInteger.ONE; // product over j != i of (alpha[i] - alpha[j])
            for (int j = 1; j <= n; j++) {
                if (j == i)
                    continue;
                BigInteger diff = alpha[i].subtract(alpha[j]).mod(p);
                num = num.multiply(diff).mod(p);
            }
            // invert num mod p
            v[i - 1] = num.modInverse(p);
        }
        return v;
    }
}
