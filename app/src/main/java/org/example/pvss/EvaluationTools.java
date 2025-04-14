package org.example.pvss;

import java.math.BigInteger;

public class EvaluationTools {

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
