
package org.example.pvss;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;
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
                BigInteger[] evaluations = EvaluationTools.evalAll(polyCoeffs, xPoints, modulus);

                // Verify the results.
                assertArrayEquals("Polynomial evaluations should match", expected, evaluations);
        }

        @Test
        public void testGenerateScrapeSumTerms() {
                // Fixed small prime modulus.
                BigInteger modulus = new BigInteger("7919");
                // Number of participants.
                int n = 3;

                // Define evaluation points: we assume an array of length n+1, where index 0 is
                // unused.
                BigInteger[] evalPoints = new BigInteger[] { BigInteger.ZERO,
                                BigInteger.ONE,
                                BigInteger.valueOf(2),
                                BigInteger.valueOf(3) };
                // Define code coefficients for participants 1 to n.
                BigInteger[] codeCoeffs = new BigInteger[] { new BigInteger("2"),
                                new BigInteger("3"),
                                new BigInteger("4") };
                // Define polynomial coefficients for m*: Let [5, 7, 11].
                BigInteger[] polyCoeffs = new BigInteger[] { new BigInteger("5"),
                                new BigInteger("7"),
                                new BigInteger("11") };

                // Expected terms (as calculated above).
                BigInteger[] expectedTerms = new BigInteger[] {
                                new BigInteger("46"),
                                new BigInteger("189"),
                                new BigInteger("500")
                };

                // Call the method.
                BigInteger[] computedTerms = EvaluationTools.computeScrapeWeights(modulus, evalPoints, codeCoeffs,
                                polyCoeffs, n);

                // Check that the computed terms match the expected ones.
                assertArrayEquals("The SCRAPE sum terms must match the expected values", expectedTerms, computedTerms);
        }

        @Test
        public void testScrapeCheckOnAi() {
                // For a controlled test, we use small parameters.
                // In practice these come from your DH PVSS setup.
                int t = 2; // threshold
                int n = 5; // number of participants

                // Generate group parameters using your GroupGenerator (elliptic curve
                // secp256r1).
                GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup();

                // Set up the PVSS context.
                DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(groupParams, t, n);
                BigInteger modulus = ctx.getOrder(); // For our scalar arithmetic.
                BigInteger[] alphas = ctx.getAlphas(); // Evaluation points: indices 0 ... n.
                BigInteger[] dualCodeCoeffs = ctx.getV(); // The v_i values (of length n).

                // For the test, we choose a dummy secret. In a real case S is a point in G.
                // Here, we simulate shares A_i computed as: A_i = S + m(α_i)·G.
                // For simplicity we may set S = G * s for some s. (Here s=7, e.g.)
                BigInteger s = BigInteger.valueOf(7);
                ECPoint S_point = ctx.getGenerator().multiply(s);

                // Obtain the Shamir shares A_i.
                // We assume SSS_EC.generateSharesEC(ctx, S) returns an array of ECPoints A_i
                // for i = 1...n.
                ECPoint[] shares = GShamir_Share.generateSharesEC(ctx, S_point);
                assertNotNull("Shares should not be null", shares);
                assertEquals("There should be n shares", n, shares.length);

                // For testing m*(α_i), we define a dummy evaluation: let m*(α_i) = (α_i)^2 mod
                // modulus.
                // (For i=1 to n, since index 0 is reserved.)
                BigInteger[] evaluations = new BigInteger[n + 1];
                for (int i = 0; i <= n - 1; i++) {
                        evaluations[i] = alphas[i + 1];
                        System.out.println(evaluations[i]);
                }

                // Now, compute the SCRAPE sum T = ∑_{i=1}^{n} [v_i * m*(α_i)] * A_i.
                ECPoint aggregateTerm = ctx.getGenerator().getCurve().getInfinity();
                for (int i = 1; i <= n; i++) {
                        // Compute scalar = (m*(α_i) * v[i-1]) mod modulus.
                        BigInteger scalar = evaluations[i - 1].multiply(dualCodeCoeffs[i - 1]).mod(modulus);
                        // Multiply the share A_i by the scalar.
                        System.out.println("dualCodeCoeffs[i] : " + dualCodeCoeffs[i - 1]);
                        ECPoint term = shares[i - 1].multiply(scalar);
                        aggregateTerm = aggregateTerm.add(term);

                        System.out.println("Participant " + i + ":");
                        System.out.println(" m*(α_" + i + ") = " + evaluations[i - 1]);
                        System.out.println(" v[" + (i - 1) + "] = " + dualCodeCoeffs[i - 1]);
                        System.out.println(" scalar = " + scalar);
                        System.out.println(" term = " + term);
                }
                System.out.println("Aggregated SCRAPE sum T = " + aggregateTerm);

                // According to the SCRAPE check in the paper, T should be equal to the identity
                // element.
                ECPoint identity = ctx.getGenerator().getCurve().getInfinity();
                System.out.println("Expected identity = " + identity);
                assertEquals("Aggregate SCRAPE sum should be the identity element", identity, aggregateTerm);
        }

        public static void main(String[] args) throws Exception {

        }

}
