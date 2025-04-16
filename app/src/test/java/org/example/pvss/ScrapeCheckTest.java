package org.example.pvss;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
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
            BigInteger term = coeffs[j].multiply(x.modPow(BigInteger.valueOf(j),
                    modulus)).mod(modulus);
            result = result.add(term).mod(modulus);

        }
        return result;
    }

    @Test
    public void testScrapeCheckOnManualEllipticShares() {
        // 1) Set up curve + parameters
        GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup();
        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(groupParams, /* t= */2, /* n= */5);
        ECPoint G = ctx.getGenerator();
        BigInteger p = ctx.getOrder(); // group order
        BigInteger[] alphas = ctx.getAlphas(); // [α₀,α₁…α₅]

        // 2) Pick a small-degree sharing polynomial m(X)=a0 + a1·X + a2·X^2 (deg ≤ t)
        BigInteger a0 = BigInteger.valueOf(11);
        BigInteger a1 = BigInteger.valueOf(17);
        BigInteger a2 = BigInteger.valueOf(23);

        // 3) Manually generate the EC‑shares: A_i = S + m(α_i)*G
        ECPoint[] shares = new ECPoint[5];
        for (int i = 1; i <= 5; i++) {
            BigInteger xi = alphas[i].mod(p);
            BigInteger mi = a0
                    .add(a1.multiply(xi))
                    .add(a2.multiply(xi.pow(2)))
                    .mod(p);
            BigInteger secret = BigInteger.valueOf(10);
            ECPoint S = G.multiply(secret);
            shares[i - 1] = S.add(G.multiply(mi));
            System.out.printf("Manual share[%d]: m(α_%d)=%s, point=%s%n",
                    i, i, mi, shares[i - 1]);
        }

        // 4) Build a test (dual) polynomial m*(X)=c0 + c1·X (deg < n-t-1 = 2)
        BigInteger c0 = BigInteger.ZERO;
        BigInteger c1 = BigInteger.valueOf(3);

        // 5) Evaluate m*(α_i) and fetch v_i
        BigInteger[] mStar = new BigInteger[alphas.length];
        BigInteger[] v = ctx.getV(); // your dual-code coefs
        for (int i = 0; i < alphas.length; i++) {
            mStar[i] = c0.add(c1.multiply(alphas[i])).mod(p);
            System.out.printf("m*(α_%d) = %s, v[%d]=%s%n",
                    i, mStar[i], i, (i > 0 ? v[i - 1] : "—"));
        }

        // 6) SCRAPE aggregation T = Σ v_i·m*(α_i)·A_i
        ECPoint T = G.getCurve().getInfinity();
        for (int i = 1; i <= 5; i++) {
            BigInteger scalar = v[i - 1].multiply(mStar[i]).mod(p);
            ECPoint term = shares[i - 1].multiply(scalar);
            System.out.printf(
                    "i=%d: scalar=v[%d]*m*(α_%d)=%s, term=%s%n",
                    i, i - 1, i, scalar, term);
            T = T.add(term);
        }

        System.out.println("Final T = " + T);
        assertTrue("SCRAPE check must yield ∞, got " + T, T.isInfinity());
    }

    @Test
    public void testScalarScrapeIdentity1() {
        GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup();
        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(groupParams, /* t= */2, /* n= */5);

        BigInteger p = ctx.getOrder(); // that prime “p” in the paper
        BigInteger[] alphas = ctx.getAlphas(); // [α₀,α₁,…,α₅]
        BigInteger[] v = ctx.getV(); // your dual‐code coefficients v₁…v₅

        // (B) Pick a sharing polynomial m(X)=a0 + a1·X + a2·X^2, deg≤t=2
        BigInteger a0 = BigInteger.valueOf(11);
        BigInteger a1 = BigInteger.valueOf(17);
        BigInteger a2 = BigInteger.valueOf(23);

        // Build the **scalar** shares δᵢ = m(αᵢ) mod p, for i=1…5
        BigInteger[] delta = new BigInteger[5];
        for (int i = 1; i <= 5; i++) {
            BigInteger x = alphas[i].mod(p);
            delta[i - 1] = a0
                    .add(a1.multiply(x))
                    .add(a2.multiply(x.pow(2)))
                    .mod(p);
            System.out.printf("δ_%d = m(α_%d) = %s%n", i, i, delta[i - 1]);
        }

        // (C) Pick a test (dual) polynomial m*(X)=c0 + c1·X, deg< n−t−1 = 2
        BigInteger c0 = BigInteger.ZERO;
        BigInteger c1 = BigInteger.valueOf(3);

        // Evaluate m*(αᵢ) and form the final sum
        BigInteger total = BigInteger.ZERO;
        for (int i = 1; i <= 5; i++) {
            BigInteger mStar = c0.add(c1.multiply(alphas[i])).mod(p);
            BigInteger term = v[i - 1].multiply(mStar).multiply(delta[i - 1]).mod(p);
            System.out.printf(
                    "i=%d: v=%s, m*(α_%d)=%s, δ_%d=%s,  v·m*·δ = %s%n",
                    i, v[i - 1], i, mStar, i, delta[i - 1], term);
            total = total.add(term).mod(p);
        }

        System.out.println("Σ vᵢ·m*(αᵢ)·δᵢ mod p = " + total);
        assertEquals(BigInteger.ZERO, total);
    }

    @Test
    public void testScrapeCheckOnShares() {
        // 1) Curve params
        X9ECParameters params = CustomNamedCurves.getByName("secp256r1");
        BigInteger groupOrd = params.getN(); // ≈ the "p" in the SCRAPE paper
        ECPoint G = params.getG();

        // 2) Shamir + SCRAPE parameters
        int t = 2, n = 5;
        // α₀…α₅ = 0,1,2,3,4,5 (in Z_n)
        BigInteger[] alphas = new BigInteger[n + 1];
        for (int i = 0; i <= n; i++)
            alphas[i] = BigInteger.valueOf(i);

        // Precompute v₁…v₅ mod groupOrd
        BigInteger[] v = new BigInteger[n];
        for (int i = 1; i <= n; i++) {
            BigInteger prod = BigInteger.ONE;
            for (int j = 1; j <= n; j++) {
                if (i == j)
                    continue;
                BigInteger diff = alphas[i].subtract(alphas[j]).mod(groupOrd);
                prod = prod.multiply(diff.modInverse(groupOrd)).mod(groupOrd);
            }
            v[i - 1] = prod;
        }

        // 3) Dealer secret S = s·G
        BigInteger secretScalar = BigInteger.valueOf(7).mod(groupOrd);
        ECPoint S = G.multiply(secretScalar);

        // 4) Manually build shares A_i = S + m(α_i)·G
        // with m(X)=a0 + a1·X + a2·X^2 (deg≤t)
        BigInteger a0 = BigInteger.valueOf(11),
                a1 = BigInteger.valueOf(17),
                a2 = BigInteger.valueOf(23);
        ECPoint[] shares = new ECPoint[n];
        for (int i = 1; i <= n; i++) {
            BigInteger x = alphas[i];
            BigInteger mi = a0
                    .add(a1.multiply(x))
                    .add(a2.multiply(x.pow(2)))
                    .mod(groupOrd);
            shares[i - 1] = S.add(G.multiply(mi));
        }

        // 5) Pick a challenge poly m*(X)=c1·X (deg< n-t-1 = 2)
        BigInteger c1 = BigInteger.valueOf(3).mod(groupOrd);

        // 6) SCRAPE aggregation: T = Σ v_i · m*(α_i) · A_i
        ECPoint T = G.getCurve().getInfinity();
        for (int i = 1; i <= n; i++) {
            BigInteger mStar = c1.multiply(alphas[i]).mod(groupOrd);
            BigInteger scalar = v[i - 1].multiply(mStar).mod(groupOrd);
            T = T.add(shares[i - 1].multiply(scalar));
        }

        // 7) Check it collapses to infinity
        assertTrue("SCRAPE check must yield ∞ but got " + T, T.isInfinity());
    }

    @Test
    public void testScrapeCheckOnSharesUsingCtx() {
        // 1) Build your PVSS context exactly as in production
        int t = 2, n = 5;
        GroupGenerator.GroupParameters gp = GroupGenerator.generateGroup();
        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(gp, t, n);
        ECPoint G = ctx.getGenerator();
        // 2) Extract the subgroup order (the “p” in the paper) and generator
        BigInteger p = ctx.getOrder(); // subgroup order, NOT the field prime

        // 3) Grab the evaluation points α₀…αₙ and the dual‐code coefs v₁…vₙ
        BigInteger[] alphas = ctx.getAlphas(); // length n+1, α₀…α₅
        BigInteger[] v = ctx.getV(); // length n = 5

        // 4) Pick a small degree‑t polynomial m(X)=a0 + a1·X + a2·X^2
        BigInteger a0 = BigInteger.valueOf(11),
                a1 = BigInteger.valueOf(17),
                a2 = BigInteger.valueOf(23);

        // 5) Dealer chooses secret scalar s and S = s·G
        BigInteger secretScalar = BigInteger.valueOf(7).mod(p);
        ECPoint S = G.multiply(secretScalar);

        // 6) Manually build the shares A_i = S + m(α_i)·G
        ECPoint[] shares = new ECPoint[n];
        for (int i = 1; i <= n; i++) {
            BigInteger xi = alphas[i].mod(p);
            BigInteger mi = a0
                    .add(a1.multiply(xi))
                    .add(a2.multiply(xi.pow(2)))
                    .mod(p);
            shares[i - 1] = S.add(G.multiply(mi));
        }

        // 7) Choose a dual‐code challenge m*(X)=c1·X (deg < n−t−1 = 2)
        BigInteger c1 = BigInteger.valueOf(3).mod(p);

        // 8) Perform the SCRAPE aggregation T = Σ v_i·m*(α_i)·A_i
        ECPoint T = G.getCurve().getInfinity();
        for (int i = 1; i <= n; i++) {
            BigInteger mStar = c1.multiply(alphas[i]).mod(p);
            BigInteger scalar = v[i - 1].multiply(mStar).mod(p);
            T = T.add(shares[i - 1].multiply(scalar));
        }

        // 9) Assert it collapses to infinity
        assertTrue("SCRAPE check must yield infinity, but got: " + T, T.isInfinity());
    }

    public static void main(String[] args) throws Exception {

        // test.testDualCodeCoefficients_Simple();
        // test.testScrapeCheckIdentity();

    }
}