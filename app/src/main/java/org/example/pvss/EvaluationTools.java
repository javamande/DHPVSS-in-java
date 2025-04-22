package org.example.pvss;

import java.math.BigInteger;

/**
 * DHPVSS evaluation utilities in the YOLO YOSO model.
 * All arithmetic is done in the prime field ℤp (the subgroup order of the EC
 * group).
 */
public class EvaluationTools {

    /**
     * Compute, for each role i=1…n, the SCRAPE “weighted evaluation” rᵢ · m*(αᵢ):
     *
     * m*(X) = ∑_{j=0}^{d} cⱼ·X^j // hash‑derived polynomial of degree d=n−t−2
     * rᵢ = vᵢ·m*(αᵢ) mod p // dual‑code coeff vᵢ · evaluation at αᵢ
     *
     * @param p subgroup order (prime modulus)
     * @param α evaluation points [0…n], use only α[1…n]
     * @param v dual‑code coefficients [v₁…vₙ]
     * @param c polynomial coefficients [c₀…c_d] for m*(X)
     * @param n total number of roles/participants
     * @return array r[0…n−1] where r[i] = r_{i+1} = v_{i+1}·m*(α_{i+1}) mod p
     */
    public static BigInteger[] computeScrapeWeights(
            BigInteger p,
            BigInteger[] α,
            BigInteger[] v,
            BigInteger[] c,
            int n) {
        BigInteger[] r = new BigInteger[n];
        for (int i = 1; i <= n; i++) {
            // evaluate m*(αᵢ)
            BigInteger eval = BigInteger.ZERO;
            BigInteger xPow = BigInteger.ONE; // αᵢ⁰
            for (int j = 0; j < c.length; j++) {
                eval = eval.add(c[j].multiply(xPow)).mod(p);
                xPow = xPow.multiply(α[i]).mod(p);
            }
            // multiply by dual‑code coefficient vᵢ
            r[i - 1] = v[i - 1].multiply(eval).mod(p);
        }
        return r;
    }

    /**
     * Evaluate the hash‑derived polynomial m*(X) at a single point αᵢ:
     *
     * m*(αᵢ) = ∑_{j=0}^{d} cⱼ·(αᵢ)^j mod p
     *
     * @param c polynomial coefficients [c₀…c_d]
     * @param α evaluation point αᵢ
     * @param p subgroup order (prime modulus)
     * @return the field value m*(αᵢ)
     */
    public static BigInteger evaluatePolynomial(BigInteger[] c, BigInteger α, BigInteger p) {
        BigInteger result = BigInteger.ZERO;
        BigInteger xPow = BigInteger.ONE;
        for (BigInteger coeff : c) {
            result = result.add(coeff.multiply(xPow)).mod(p);
            xPow = xPow.multiply(α).mod(p);
        }
        return result;
    }

    /**
     * Batch‑evaluate m*(X) at all α[1…n]:
     *
     * @param c polynomial coefficients [c₀…c_d]
     * @param α evaluation points [0…n]
     * @param p subgroup order (prime modulus)
     * @return array evals[0…n] with evals[i] = m*(α[i]) (note index 0 is unused)
     */
    public static BigInteger[] evalAll(BigInteger[] c, BigInteger[] α, BigInteger p) {
        BigInteger[] out = new BigInteger[α.length];
        for (int i = 1; i < α.length; i++) {
            out[i] = evaluatePolynomial(c, α[i], p);
        }
        return out;
    }
}
