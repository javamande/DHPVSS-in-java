package org.example.pvss;

import java.math.BigInteger;

import org.junit.Test;

public class testComputeFirstRoundForParty {
    @Test
    public void testHashStrectch() {
        int n = 6, t = 3;

        // Generate group parameters over the elliptic curve secp256r1.
        GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup();

        // Call the actual setup function. This internally computes the evaluation
        // points (alphas)
        // as 0, 1, …, n and calculates dual-code coefficients (vs) from the inverse
        // table.
        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(groupParams, t, n);
        BigInteger[] alphas = ctx.getAlphas();
        BigInteger p = ctx.getOrder();

        // Make a “known” hash‐stretch polynomial:
        BigInteger zero = BigInteger.ZERO;
        BigInteger one = BigInteger.ONE;
        BigInteger[] mStar = new BigInteger[n - t];
        mStar[0] = zero;
        mStar[1] = one; // pretend seed=1
        mStar[2] = BigInteger.valueOf(2);
        mStar[3] = BigInteger.valueOf(3);

        // Now evaluate it at each alpha and verify:
        for (int j = 1; j <= n; j++) {
            BigInteger val = EvaluationTools.evaluatePolynomial(mStar, alphas[j], p);
            // should equal mStar[0] + mStar[1]*α + mStar[2]*α^2 + mStar[3]*α^3
            BigInteger expected = zero
                    .add(one.multiply(alphas[j]))
                    .add(BigInteger.valueOf(2).multiply(alphas[j].pow(2)))
                    .add(BigInteger.valueOf(3).multiply(alphas[j].pow(3)))
                    .mod(p);
            System.out.printf("j=%d: eval=%s  expected=%s  ok=%b%n",
                    j, val.toString(16), expected.toString(16), val.equals(expected));
        }
    }
}