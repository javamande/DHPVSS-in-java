
package org.example.pvss;

import java.math.BigInteger;

public class ScrapeCheck {

    // Compute modular inverse using BigInteger.
    public static int modInverse(int a, int p) {
        return BigInteger.valueOf(a).modInverse(BigInteger.valueOf(p)).intValue();
    }

    // Compute modular exponentiation.
    public static int modPow(int base, int exp, int p) {
        return BigInteger.valueOf(base).modPow(BigInteger.valueOf(exp), BigInteger.valueOf(p)).intValue();
    }

    // Evaluates a polynomial represented as an array of coefficients [a0, a1, a2,
    // …]
    // at the given x modulo p.
    public static int evaluatePolynomial(int[] coeffs, int x, int p) {
        int result = 0;
        int power = 1; // x^0 initially
        for (int coeff : coeffs) {
            result = (result + coeff * power) % p;
            power = (power * x) % p;
        }
        return (result + p) % p;
    }

    // Generate shares by evaluating the polynomial at each alpha.
    public static int[] generateShares(int[] coeffs, int[] alphas, int p) {
        int n = alphas.length;
        int[] shares = new int[n];
        for (int i = 0; i < n; i++) {
            shares[i] = evaluatePolynomial(coeffs, alphas[i], p);
        }
        return shares;
    }

    // Compute the SCRAPE coefficients v_i for the provided evaluation points.
    // v_i = ∏(for all j ≠ i) (alpha_i - alpha_j)⁻¹ mod p.
    public static int[] computeV(int[] alphas, int p) {
        int n = alphas.length;
        int[] v = new int[n];
        for (int i = 0; i < n; i++) {
            int prod = 1;
            for (int j = 0; j < n; j++) {
                if (j != i) {
                    int diff = (alphas[i] - alphas[j]) % p;
                    if (diff < 0)
                        diff += p;
                    prod = (prod * diff) % p;
                }
            }
            // v[i] is the modular inverse of the product.
            v[i] = modInverse(prod, p);
        }
        return v;
    }

    /**
     * Checks whether the share vector `shares` is a valid Shamir sharing of degree
     * t.
     * It does so by checking that for every basis polynomial m*(X)=X^k (with k =
     * 0,..., n-t-1),
     * the sum Σ (v_i * m*(alpha_i) * share[i]) modulo p equals 0.
     */
    public static boolean scrapeCheck(int[] shares, int[] alphas, int p, int t) {
        int n = alphas.length;
        int dualDegree = n - t - 1; // The dual space is spanned by monomials X^0,...,X^(dualDegree)
        int[] v = computeV(alphas, p);
        // For each basis polynomial m*(X)=X^k:
        for (int k = 0; k <= dualDegree; k++) {
            int sum = 0;
            for (int i = 0; i < n; i++) {
                // Compute m*(alpha_i) = alpha_i^k mod p.
                int mStarAtAlpha = modPow(alphas[i], k, p);
                sum = (sum + ((v[i] * mStarAtAlpha) % p * shares[i]) % p) % p;
            }
            if (sum % p != 0) {
                return false; // Fails the SCRAPE check for this basis polynomial.
            }
        }
        return true;
    }
}
