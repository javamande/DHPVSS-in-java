package org.example.pvss;

import java.math.BigInteger;

public class EvaluationTools {

    /**
     * Generates the SCRAPE sum terms for each participant.
     * For each participant x (using evaluation point evalPoints[x] for x=1..n),
     * it computes:
     * poly_eval = Σ (polyCoeffs[i] · (evalPoints[x])^i) mod modulus,
     * term[x-1] = codeCoeffs[x-1] · poly_eval mod modulus.
     *
     * @param modulus       the prime modulus used in the arithmetic
     * @param evalPoints    the evaluation points (an array of BigIntegers; index 0
     *                      is unused,
     *                      indices 1..n are used)
     * @param codeCoeffs    the code coefficients for participants (length = n)
     * @param polyCoeffs    the polynomial coefficients (length = numPolyCoeffs)
     * @param n             the number of participants
     * @param numPolyCoeffs the number of polynomial coefficients
     * @return an array of BigIntegers representing the SCRAPE sum terms for each
     *         participant.
     */
    public static BigInteger[] generateScrapeSumTerms(BigInteger modulus,
            BigInteger[] evalPoints,
            BigInteger[] codeCoeffs,
            BigInteger[] polyCoeffs,
            int n, int numPolyCoeffs) {
        BigInteger[] terms = new BigInteger[n];
        // For each participant x = 1 ... n:
        for (int x = 1; x <= n; x++) {
            BigInteger evalPoint = evalPoints[x]; // recall: evalPoints[0] is unused
            BigInteger polyEval = BigInteger.ZERO;
            // Compute polyEval = sum{i=0}^{numPolyCoeffs - 1} polyCoeffs[i] * (evalPoint)^i
            // mod modulus.
            for (int i = 0; i < numPolyCoeffs; i++) {
                BigInteger term = evalPoint.modPow(BigInteger.valueOf(i), modulus)
                        .multiply(polyCoeffs[i]).mod(modulus);
                polyEval = polyEval.add(term).mod(modulus);
            }
            // Multiply by the corresponding code coefficient.
            terms[x - 1] = codeCoeffs[x - 1].multiply(polyEval).mod(modulus);
        }
        return terms;
    }

    /**
     * Evaluates the polynomial m*(X) at point x.
     */
    public static BigInteger evaluatePolynomial(BigInteger[] polyCoeffs, BigInteger x, BigInteger modulus) {
        BigInteger result = BigInteger.ZERO;

        for (int j = 0; j < polyCoeffs.length; j++) {
            // term = polyCoeffs[j] * (x^j mod modulus)
            BigInteger term = polyCoeffs[j].multiply(x.modPow(BigInteger.valueOf(j), modulus)).mod(modulus);
            result = result.add(term).mod(modulus);
        }
        return result;
    }

    public static BigInteger[] evaluatePolynomialAtAllPoints(BigInteger[] polyCoeffs, BigInteger[] xPoints,
            BigInteger modulus) {
        BigInteger[] evaluations = new BigInteger[xPoints.length];
        for (int i = 0; i < xPoints.length; i++) {
            evaluations[i] = evaluatePolynomial(polyCoeffs, xPoints[i], modulus);
        }
        return evaluations;
    }

}
