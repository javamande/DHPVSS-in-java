package org.example.pvss;

import java.math.BigInteger;
import java.util.Arrays;

import org.bouncycastle.math.ec.ECPoint;

public class DHPVSSDistributionVerifier {

    /**
     * Verifies the distribution proof.
     *
     * @param ctx             the PVSS context containing public parameters.
     * @param proof           the DLEQ proof produced during distribution.
     * @param encryptedShares the array of encrypted shares.
     * @param pubDist         the dealer’s public key.
     * @param comKeys         the array of commitment keys.
     * @return true if the proof verifies, false otherwise.
     */

    public static boolean dhPvssDistributeVerify(DhPvssContext ctx,
            NizkDlEqProof proof,
            ECPoint[] encryptedShares,
            ECPoint pubDist,
            ECPoint[] comKeys) {
        BigInteger p = ctx.getOrder();
        int n = ctx.getNumParticipants();
        int t = ctx.getThreshold();
        int numPolyCoeffs = n - t - 1; // Degree is n-t-2, so number of coefficients = n-t-1.
        System.out.println("=== Distribution Verification Debug ===");
        System.out.println("n = " + n + ", t = " + t + ", numPolyCoeffs = " + numPolyCoeffs);
        System.out.println("Dealer's public key: " + pubDist);
        System.out.println("Encrypted shares: " + Arrays.toString(encryptedShares));
        System.out.println("Commitment keys: " + Arrays.toString(comKeys));

        // Step 1: Compute polynomial coefficients.
        BigInteger[] polyCoeffs = HashingTools.hashPointsToPoly(pubDist, comKeys, encryptedShares, numPolyCoeffs, p);
        System.out.println("Polynomial coefficients:");
        for (int i = 0; i < polyCoeffs.length; i++) {
        }

        // Step 2: Generate scrape sum terms.
        BigInteger[] scrapeTerms = new BigInteger[n];
        BigInteger[] alphas = ctx.getAlphas();
        BigInteger[] vs = ctx.getV();

        for (int i = 0; i < n; i++) {
            BigInteger alpha_i = alphas[i + 1]; // evaluation point for participant i+1
            BigInteger polyEval = BigInteger.ZERO;
            System.out.println("For participant " + (i + 1) + " (α=" + alpha_i + "):");
            for (int j = 0; j < numPolyCoeffs; j++) {
                BigInteger term = alpha_i.modPow(BigInteger.valueOf(j), p)
                        .multiply(polyCoeffs[j]).mod(p);
                polyEval = polyEval.add(term).mod(p);
            }
            scrapeTerms[i] = vs[i].multiply(polyEval).mod(p);
        }

        // Step 3: Compute weighted sums U and V.
        BigInteger U = BigInteger.ONE;
        BigInteger V = BigInteger.ONE;
        for (int i = 0; i < n; i++) {
            // For each participant, raise the commitment key and encrypted share to its
            // scrape term.
            BigInteger termU = comKeys[i].modPow(scrapeTerms[i], p);
            BigInteger termV = encryptedShares[i].modPow(scrapeTerms[i], p);
            U = U.multiply(termU).mod(p);
            V = V.multiply(termV).mod(p);

        }
        BigInteger dealerSecret = BigInteger.valueOf(13);

        System.out.println("Computed weighted sum U: " + U);
        BigInteger expectedV = U.modPow(dealerSecret, p);
        System.out.println("Expected V (U^(dealerSecret) mod p): " + expectedV);
        System.out.println("Computed V: " + V);
        System.out.println(" ");
        // Step 4: Verify the DLEQ proof.
        boolean valid = NizkDlEqProofGenerator.verifyProof(ctx, U, pubDist, V, proof);
        System.out.println("DLEQ proof verification result: " + valid);
        System.out.println("=== End Distribution Verification Debug ===\n");
        return valid;
    }
}
