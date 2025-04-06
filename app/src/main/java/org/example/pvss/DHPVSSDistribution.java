package org.example.pvss;

import java.math.BigInteger;

public class DHPVSSDistribution {

    /**
     * Container class for the result of distribution: the encrypted shares and the
     * DLEQ proof.
     */
    public static class DistributionResult {
        private final BigInteger[] encryptedShares;
        private final NizkDlEqProof proof;

        public DistributionResult(BigInteger[] encryptedShares, NizkDlEqProof proof) {
            this.encryptedShares = encryptedShares;
            this.proof = proof;
        }

        public BigInteger[] getEncryptedShares() {
            return encryptedShares;
        }

        public NizkDlEqProof getProof() {
            return proof;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("DistributionResult{\n");
            sb.append("  encryptedShares: [\n");
            for (BigInteger share : encryptedShares) {
                sb.append("    ").append(share).append("\n");
            }
            sb.append("  ],\n");
            sb.append("  proof: ").append(proof).append("\n");
            sb.append("}");
            return sb.toString();
        }
    }

    /**
     * Distributes a secret S and generates a DLEQ proof that the dealer correctly
     * encrypted the shares.
     *
     * This method implements the distribution phase of DHPVSS as follows:
     *
     * 1. **Shamir Share Generation:**
     * Compute shares A_i = m(α_i) for i = 1,...,n, where
     * m(X) = secret + a₁ X + ... + aₜ Xᵗ mod p.
     *
     * 2. **Encryption of Shares:**
     * For each participant i, encrypt the share as:
     * C_i = A_i + sk_D * E_i mod p,
     * where E_i is the commitment key for participant i.
     *
     * 3. **Polynomial and SCRAPE Coefficients:**
     * Compute a set of polynomial coefficients by hashing (distKey.pub, comKeys,
     * encryptedShares)
     * to obtain polyCoeffs. Then, for each participant, compute a “scrape term”:
     * scrapeTerm[i] = v_i * (Σ_{j=0}^{numPolyCoeffs-1} α_i^j * polyCoeffs[j]) mod
     * p.
     *
     * 4. **Weighted Sum Computation:**
     * Compute U = Σ scrapeTerm[i] * comKeys[i] mod p and
     * V = Σ scrapeTerm[i] * encryptedShares[i] mod p.
     * If the shares A_i satisfy the dual-code condition (Σ λ_i * A_i = 0), then:
     * V = sk_D * U mod p.
     *
     * 5. **DLEQ Proof Generation:**
     * Generate a DLEQ proof that proves the discrete logarithm equality:
     * g^(sk_D) = distKey.pub and U^(sk_D) = V.
     * This shows that the same dealer secret was used in both the key and the
     * encryption.
     *
     * @param ctx     The DHPVSS context containing public parameters pp = (G, G, p,
     *                t, n, {α_i}).
     * @param comKeys The array of commitment keys E_i (one per participant), each
     *                in Z_p.
     * @param distKey The dealer's key pair (sk_D, distKey.pub).
     * @param secret  The secret S ∈ Z_p to be shared.
     * @return A DistributionResult containing the encrypted shares and the DLEQ
     *         proof.
     */
    public static DistributionResult dhPvssDistributeProve(DhPvssContext ctx,
            BigInteger[] comKeys,
            DhKeyPair distKey,
            BigInteger secret) {
        BigInteger S = ctx.getGenerator().modPow(secret, ctx.getOrder());

        int n = ctx.getNumParticipants();
        int t = ctx.getThreshold();
        BigInteger p = ctx.getOrder(); // Prime modulus.
        BigInteger[] alphas = ctx.getAlphas(); // Evaluation points: α₀, α₁, …, αₙ.
        BigInteger[] vs = ctx.getV(); // Dual-code coefficients, as provided by the context.

        // 1. Generate Shamir shares.
        // Each share A_i is computed as A_i = m(α_i) mod p, where
        // m(X) = secret + a₁ X + ... + aₜ Xᵗ mod p.
        BigInteger[] shares = SSSStandard.generateSharesStandard(ctx, S);

        // 2. Encrypt shares using the dealer's secret key sk_D.
        // For each participant i, compute the encrypted share:
        // C_i = A_i + sk_D * E_i mod p,
        // where E_i = comKeys[i].
        // For each participant i, compute:
        // C_i = A_i * (comKeys[i])^(sk_D) mod p.
        BigInteger[] encryptedShares = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            encryptedShares[i] = shares[i].multiply(comKeys[i].modPow(distKey.getSecretKey(), p)).mod(p);
        }

        // 3. Compute the polynomial coefficients used for the SCRAPE test.
        // We compute polyCoeffs = HashPointsToPoly(distKey.pub, comKeys,
        // encryptedShares, numPolyCoeffs, p),
        // where numPolyCoeffs = n - t - 1. These coefficients implicitly define a
        // polynomial
        // whose evaluations at the points α_i are used as weights (λ_i).
        int numPolyCoeffs = n - t - 1;
        BigInteger[] polyCoeffs = HashingTools.hashPointsToPoly(distKey.getPublic(), comKeys, encryptedShares,
                numPolyCoeffs, p);

        // 4. Compute the "scrape sum" terms for each participant.
        // For each participant i (with evaluation point α_i, for i = 1,…, n),
        // compute:
        // polyEval_i = Σ_{j=0}^{numPolyCoeffs-1} (α_i^j * polyCoeffs[j]) mod p,
        // and then set:
        // scrapeTerm[i] = v_i * polyEval_i mod p.
        // In an ideal implementation (e.g., via the SCRAPE test), the shares A_i are
        // chosen
        // so that Σ scrapeTerm[i] * A_i ≡ 0, ensuring that the random part cancels.
        BigInteger[] scrapeTerms = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            BigInteger alpha_i = alphas[i + 1]; // Use α_{i+1} since α₀ is reserved.
            BigInteger polyEval = BigInteger.ZERO;
            for (int j = 0; j < numPolyCoeffs; j++) {
                BigInteger term = alpha_i.modPow(BigInteger.valueOf(j), p)
                        .multiply(polyCoeffs[j]).mod(p);
                polyEval = polyEval.add(term).mod(p);
            }
            // Multiply by the dual-code coefficient for participant i.
            scrapeTerms[i] = vs[i].multiply(polyEval).mod(p);
        }

        // 5. Compute the weighted sums U and V.
        // Let λ_i = scrapeTerms[i]. Then compute:
        // U = ∏_{i=1}^{n} (comKeys[i])^(λ_i) mod p.
        // V = ∏_{i=1}^{n} (encryptedShares[i])^(λ_i) mod p.
        BigInteger U = BigInteger.ONE;
        BigInteger V = BigInteger.ONE;
        for (int i = 0; i < n; i++) {
            U = U.multiply(comKeys[i].modPow(scrapeTerms[i], p)).mod(p);
            V = V.multiply(encryptedShares[i].modPow(scrapeTerms[i], p)).mod(p);
            System.out.println("For participant " + (i + 1) + ":");
            System.out.println("  comKey^scrapeTerm = " + comKeys[i].modPow(scrapeTerms[i], p));
            System.out.println("  encryptedShare^scrapeTerm = " + encryptedShares[i].modPow(scrapeTerms[i], p));

        }
        System.out.println("=== Distribution Prove Debug ===");
        System.out.println("Computed weighted sum U: " + U);
        BigInteger expectedV = U.modPow(distKey.getSecretKey(), p);
        System.out.println("Expected V (U^(dealerSecret) mod p): " + expectedV);
        System.out.println("Computed V: " + V);

        // 6. Generate the DLEQ proof.
        // The DLEQ proof will demonstrate that the same dealer secret sk_D was used to
        // compute the dealer's public key and to encrypt the shares.
        // In our finite-field setting, we want to show:
        // distKey.pub = g^(sk_D) mod p
        // and
        // V = U^(sk_D) mod p,
        // which is equivalent to proving the discrete logarithm equality:
        // DL(g, distKey.pub) = DL(U, V).
        // We call our DLEQ proof generator with:
        // - The fixed generator g from the context,
        // - The dealer's public key x = distKey.pub,
        // - The second base h = U,
        // - The value y = V,
        // - And the dealer's secret sk_D.
        NizkDlEqProof dleqProof = NizkDlEqProofGenerator.generateProof(ctx, U, distKey.getPublic(), V,
                distKey.getSecretKey());

        // 7. Return the distribution result.
        return new DistributionResult(encryptedShares, dleqProof);
    }
}
