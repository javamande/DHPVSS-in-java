package org.example.pvss;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;

public class ScrapeCheckTest {

    /**
     * Evaluates a polynomial f(x) given its coefficients.
     * The polynomial is given in standard form:
     * f(x) = c0 + c1*x + c2*x^2 + ... + c_t*x^t.
     *
     * @param coeffs  the polynomial coefficients (length = degree + 1)
     * @param x       the evaluation point
     * @param modulus the modulus for the arithmetic
     * @return f(x) mod modulus.
     */
    public static BigInteger evaluatePolynomial(BigInteger[] coeffs, BigInteger x, BigInteger modulus) {
        BigInteger result = BigInteger.ZERO;
        for (int j = 0; j < coeffs.length; j++) {
            BigInteger term = coeffs[j].multiply(x.modPow(BigInteger.valueOf(j), modulus)).mod(modulus);
            result = result.add(term).mod(modulus);

        }
        return result;
    }

    @Test
    public void testScrapeAggregation_SimpleCase() {
        // Use a small prime modulus for testing.
        BigInteger modulus = new BigInteger("7919");
        // Get the dummy generator (which represents G in our dummy group).
        DummyECPoint G = DummyECPoint.getGenerator(modulus);

        // Set n = 3 participants.
        int n = 3;

        // For simplicity, let our “hashed polynomial” evaluations be constant 1.
        // (Typically m*(α_i) would be computed from a hash-to-poly function, but here
        // we force it.)
        BigInteger[] evaluations = new BigInteger[] {
                BigInteger.ZERO, // index 0 (unused, since the theorem uses i=1,...,n)
                BigInteger.ONE, // m*(α_1)=1
                BigInteger.ONE, // m*(α_2)=1
                BigInteger.ONE // m*(α_3)=1
        };

        // Choose dual‑code coefficients so that they sum to 0 modulo modulus.
        // For example, take: v1=1, v2=2, and v3=7919 - 3 = 7916.
        BigInteger[] v = new BigInteger[] {
                new BigInteger("1"),
                new BigInteger("2"),
                new BigInteger("7916")
        };

        // Define dummy shares A_i = a_i * G.
        // For instance, let a1=5, a2=7, a3=8 (arbitrary small numbers).
        DummyECPoint[] A = new DummyECPoint[n];
        A[0] = G.multiply(BigInteger.valueOf(5)); // A_1 = 5*G
        A[1] = G.multiply(BigInteger.valueOf(7)); // A_2 = 7*G
        A[2] = G.multiply(BigInteger.valueOf(8)); // A_3 = 8*G

        // Now compute the SCRAPE term for each participant:
        // For i=1,...,n, term T_i = v_i * m*(α_i) * A_i.
        DummyECPoint T = DummyECPoint.infinity(modulus); // aggregate dummy point (identity)
        for (int i = 1; i <= n; i++) {
            BigInteger eval = evaluations[i]; // m*(α_i)
            BigInteger scalar = v[i - 1].multiply(eval).mod(modulus); // v_i * m*(α_i)
            DummyECPoint term = A[i - 1].multiply(scalar); // scalar multiplication on group
            System.out.println("Participant " + i + ":");
            System.out.println("  m*(α_" + i + ") = " + eval);
            System.out.println("  v[" + i + "] = " + v[i - 1]);
            System.out.println("  Scalar = " + scalar);
            System.out.println("  Term T_" + i + " = " + term);
            T = T.add(term);
        }

        // Print out the aggregated SCRAPE sum T.
        System.out.println("Aggregated SCRAPE sum T = " + T);
        // In a correct SCRAPE check, T should equal the identity element.
        DummyECPoint identity = DummyECPoint.infinity(modulus);
        System.out.println("Expected identity = " + identity);
        assertEquals("SCRAPE check should yield the identity element", identity, T);
    }

    @Test
    public void testScrapeCheckOnShares() {
        // Use a moderately sized prime from the EC group from secp256r1.
        GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup();
        int t = 2; // threshold (degree t polynomial)
        int n = 5; // number of participants

        // Set up the PVSS context.
        DhPvssContext ctx = DhPvssUtils.dhPvssSetup(groupParams, t, n);
        // The modulus is the characteristic of the underlying field.
        BigInteger modulus = ctx.getOrder();

        // Choose a fixed dealer secret scalar s and compute the dealer secret group
        // element S = G * s.
        BigInteger secretScalar = BigInteger.valueOf(7);
        ECPoint S = ctx.getGenerator().multiply(secretScalar);

        // Generate the EC-based Shamir shares A_i = S + m(α_i)*G.
        // (Note: Our SSS_EC.generateSharesEC should already incorporate the convention
        // m(α₀)=0.)
        ECPoint[] shares = SSS_EC.generateSharesEC(ctx, S);

        // For the SCRAPE check, we choose a random challenge polynomial m*(x) of low
        // degree.
        // Per the protocol, m*(x) is a polynomial of degree < (n - t - 1). For
        // simplicity,
        // choose degree 1: m*(x) = 0 + c1*x, i.e. m*(0)=0.
        BigInteger[] challengePoly = new BigInteger[2]; // coefficients for degree 1 polynomial.
        challengePoly[0] = BigInteger.ZERO; // Ensure m*(0) = 0.
        // For deterministic testing, you might choose a fixed value for c1.
        challengePoly[1] = BigInteger.valueOf(3); // for example

        // Evaluate m*(x) at each evaluation point α_i.
        // ctx.getAlphas() returns an array [α₀, α₁, ... , αₙ]. We evaluate at i =
        // 1...n.
        BigInteger[] evaluations = new BigInteger[n + 1];
        BigInteger[] alphas = ctx.getAlphas(); // already generated in the context.
        for (int i = 0; i <= n; i++) {
            evaluations[i] = evaluatePolynomial(challengePoly, alphas[i], modulus);
        }

        // Retrieve the dual-code coefficients (v's) from the context.
        BigInteger[] vs = ctx.getV();
        // Aggregate T = sum_{i=1}^{n} (v_i * m*(α_i) * A_i).
        // Since group operations on EC points are additive, we compute the EC point
        // sum.
        ECPoint T = ctx.getGenerator().getCurve().getInfinity();
        for (int i = 1; i <= n; i++) {
            // Compute scalar_i = evaluations[i] * v[i-1] mod modulus.
            BigInteger scalar = evaluations[i].multiply(vs[i - 1]).mod(modulus);
            // Multiply share A_i (an ECPoint) by scalar.
            ECPoint term = shares[i - 1].multiply(scalar);
            // Add the term to the running total.
            T = T.add(term);
            System.out.println("Participant " + i + ": evaluation = " + evaluations[i] +
                    ", v = " + vs[i - 1] +
                    ", scalar = " + scalar +
                    ", term = " + term);
        }

        // Log the aggregated T.
        System.out.println("Aggregated T = " + T);

        // The SCRAPE check expects that T should be the identity element (point at
        // infinity).
        assertTrue("SCRAPE check failed: the aggregated value T is not at infinity", T.isInfinity());
    }

    public static void main(String[] args) {
        ScrapeCheckTest test = new ScrapeCheckTest();
        test.testScrapeAggregation_SimpleCase();

    }
}
