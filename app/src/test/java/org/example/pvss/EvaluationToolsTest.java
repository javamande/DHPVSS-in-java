
package org.example.pvss;

import static org.junit.Assert.assertArrayEquals;

import java.math.BigInteger;

import org.junit.Test;

public class EvaluationToolsTest {

    @Test
    public void testEvaluatePolynomialAtAllPoints() {
        // Use a small prime for testing
        BigInteger modulus = BigInteger.valueOf(101);
        // Define a polynomial f(x) = 2 + 3x + 5x^2 mod 101,
        // which in coefficient array form is:
        BigInteger[] polyCoeffs = new BigInteger[] {
                BigInteger.valueOf(2), // coefficient for x^0
                BigInteger.valueOf(3), // coefficient for x^1
                BigInteger.valueOf(5) // coefficient for x^2
        };

        // Define evaluation points [1, 2, 3, 4]
        BigInteger[] xPoints = new BigInteger[] {
                BigInteger.valueOf(1),
                BigInteger.valueOf(2),
                BigInteger.valueOf(3),
                BigInteger.valueOf(4)
        };

        // Expected evaluations:
        // f(1) = 2+3+5 = 10 mod 101
        // f(2) = 2+6+20 = 28 mod 101
        // f(3) = 2+9+45 = 56 mod 101
        // f(4) = 2+12+80 = 94 mod 101
        BigInteger[] expected = new BigInteger[] {
                BigInteger.valueOf(10),
                BigInteger.valueOf(28),
                BigInteger.valueOf(56),
                BigInteger.valueOf(94)
        };

        // Evaluate the polynomial at all points using Horner’s method.
        BigInteger[] evaluations = EvaluationTools.evaluatePolynomialAtAllPoints(polyCoeffs, xPoints, modulus);

        // Verify the results.
        assertArrayEquals("Polynomial evaluations should match", expected, evaluations);
    }
}
