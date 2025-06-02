// package test.java.org;
// package org.example.napdkg;

// /**
// * Performs the SCRAPE dual‐code consistency test over ℤₚ.
// */
// public class ScrapeCheck {

// /**
// * Compute a⁻¹ mod p.
// */
// public static int modInverse(int a, int p) {
// return java.math.BigInteger.valueOf(a)
// .modInverse(java.math.BigInteger.valueOf(p))
// .intValue();
// }

// /**
// * Compute base^exp mod p.
// */
// public static int modPow(int base, int exp, int p) {
// return java.math.BigInteger.valueOf(base)
// .modPow(java.math.BigInteger.valueOf(exp), java.math.BigInteger.valueOf(p))
// .intValue();
// }

// /**
// * Evaluate polynomial ∑ coeffs[j]·x^j over ℤₚ.
// */
// public static int evaluatePolynomial(int[] coeffs, int x, int p) {
// int res = 0, pow = 1;
// for (int c : coeffs) {
// res = (res + c * pow) % p;
// pow = (pow * x) % p;
// }
// return (res + p) % p;
// }

// /**
// * Generate shares by evaluating m(X) at each αᵢ over ℤₚ.
// */
// public static int[] generateShares(int[] coeffs, int[] alphas, int p) {
// int n = alphas.length;
// int[] shares = new int[n];
// for (int i = 0; i < n; i++) {
// shares[i] = evaluatePolynomial(coeffs, alphas[i], p);
// }
// return shares;
// }

// /**
// * Compute dual‐code weights vᵢ = ∏_{j≠i}(αᵢ−αⱼ)⁻¹ mod p.
// */
// public static int[] computeV(int[] alphas, int p) {
// int n = alphas.length, prod;
// int[] v = new int[n];
// for (int i = 0; i < n; i++) {
// prod = 1;
// for (int j = 0; j < n; j++) {
// if (i == j)
// continue;
// int diff = alphas[i] - alphas[j];
// diff %= p;
// if (diff < 0)
// diff += p;
// prod = (prod * diff) % p;
// }
// v[i] = modInverse(prod, p);
// }
// return v;
// }

// /**
// * Run SCRAPE test on share‐vector shares of degree t:
// * for each basis m*(X)=X^k, k=0…n−t−1 check ∑ vᵢ·m*(αᵢ)·shares[i] ≡ 0 mod p.
// */
// public static boolean scrapeCheck(int[] shares, int[] alphas, int p, int t) {
// int n = alphas.length;
// int dualDeg = n - t - 1;
// int[] v = computeV(alphas, p);

// for (int k = 0; k <= dualDeg; k++) {
// int sum = 0;
// for (int i = 0; i < n; i++) {
// int mStar = modPow(alphas[i], k, p);
// sum = (sum + v[i] * mStar % p * shares[i] % p) % p;
// }
// if (sum % p != 0)
// return false;
// }
// return true;
// }
// }
