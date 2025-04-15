// package org.example.pvss;

// import java.math.BigInteger;

// import org.bouncycastle.math.ec.ECPoint;

// public class DHPVSS_Dist {

//     /**
//      * Container class for the result of the distribution.
//      * It contains the array of encrypted shares and the generated DLEQ proof.
//      */
//     public static class DistributionResult {
//         private final ECPoint[] encryptedShares;
//         private final NizkDlEqProof dleqProof;

//         public DistributionResult(ECPoint[] encryptedShares, NizkDlEqProof dleqProof, boolean valid) {
//             this.encryptedShares = encryptedShares;
//             this.dleqProof = dleqProof;
//         }

//         public ECPoint[] getEncryptedShares() {
//             return encryptedShares;
//         }

//         public NizkDlEqProof getDleqProof() {
//             return dleqProof;
//         }

//         @Override
//         public String toString() {
//             StringBuilder sb = new StringBuilder();
//             sb.append("DistributionResult {\n");
//             sb.append("  Encrypted Shares:\n");
//             for (ECPoint share : encryptedShares) {
//                 sb.append("    ").append(share).append("\n");
//             }
//             sb.append("  DLEQ Proof: ").append(dleqProof).append("\n");
//             sb.append("}");
//             return sb.toString();
//         }
//     }

//     /**
//      * Distributes the secret using EC-based Shamir secret sharing.
//      * 
//      * The process is as follows:
//      * 1. Generate the Shamir shares A₁, …, Aₙ with
//      * Aᵢ = S + m(αᵢ)·G, where S is the dealer’s secret group element and m is a
//      * random polynomial with m(α₀)=0.
//      * 2. For each participant i (with ephemeral key Eᵢ), compute the encrypted
//      * share:
//      * Cᵢ = Aᵢ + (sk_D · Eᵢ)
//      * 3. Aggregate values (e.g. U and V) from the ephemeral keys and encrypted
//      * shares
//      * and generate a DLEQ proof that verifies that V = U^(sk_D).
//      *
//      * @param ctx           The PVSS context.
//      * @param ephemeralKeys An array of ephemeral public keys Eᵢ for the
//      *                      participants.
//      * @param dealerKeyPair The dealer’s key pair (containing sk_D and pk_D).
//      * @param secret        The dealer’s secret as a group element S (typically S =
//      *                      G·s).
//      * @return a DistributionResult containing the array of encrypted shares and the
//      *         DLEQ proof.
//      */
//     public static DistributionResult distribute(
//             DhPvssContext ctx,
//             ECPoint[] ephemeralKeys,
//             DhKeyPair dealerKeyPair,
//             BigInteger secret) {

//         int n = ctx.getNumParticipants();

//         // Step 1: Generate Shamir shares.
//         // In our PVSS protocol, we compute shares as:
//         // Aᵢ = S + m(αᵢ)·G, where m(α₀)=0 to “mask” out the randomness at the
//         // designated point.
//         // We assume you have an EC-based Shamir shares generator in SSS_EC.
//         ECPoint[] shares = SSS_EC.generateSharesEC(ctx, secret);

//         // Step 2: Encrypt each share using the dealer’s secret key.
//         // For each participant i, compute:
//         // Cᵢ = Aᵢ + (sk_D * Eᵢ)
//         ECPoint[] encryptedShares = new ECPoint[n];
//         for (int i = 0; i < n; i++) {
//             // Multiply ephemeral key Eᵢ by the dealer’s secret scalar sk_D. (sk_D * Eᵢ)
//             ECPoint mask = ephemeralKeys[i].multiply(dealerKeyPair.getSecretKey()).normalize();
//             // Add the mask (sk_D * Eᵢ) to the Shamir share Aᵢ, that is Aᵢ + (sk_D * Eᵢ)
//             encryptedShares[i] = shares[i].add(mask).normalize();
//         }
//         // Ci = encryptedShares[i]
//         ECPoint dealerPub = dealerKeyPair.getPublic();
//         int numPolyCoeffs = ctx.getNumParticipants() - ctx.getThreshold() - 1;
//         BigInteger modulus = ctx.getOrder();

//         BigInteger[] mHash = HashingTools.hashPointsToPoly(dealerKeyPair.getPublic(), ephemeralKeys, encryptedShares,
//                 numPolyCoeffs, modulus);

//         BigInteger[] xpoints = ctx.getAlphas();
//         BigInteger modoulus = ctx.getOrder();
//         /**
//          * Evaluates the polynomial m*(X) at point x.
//          */
//         BigInteger[] evaluations = new BigInteger[xpoints.length];
//         for (int i = 1; i < xpoints.length; i++) {
//             evaluations[i] = EvaluationTools.evaluatePolynomial(mHash, xpoints[i], modulus);
//         }

//         ECPoint U = ctx.getGenerator().getCurve().getInfinity();
//         ECPoint V = ctx.getGenerator().getCurve().getInfinity();

//         BigInteger[] vis = ctx.getV();
//         for (int i = 1; i < n; i++) {
//             // Compute mask for U and V for the ith participant:
//             // Note: Ensure that you reduce the scalar multiplications mod the subgroup
//             // order if needed.
//             BigInteger maskU = evaluations[i].multiply(vis[i]).mod(ctx.getOrder());
//             BigInteger maskV = evaluations[i].multiply(vis[i]).mod(ctx.getOrder());

//             // Compute the contribution from the ephemeral key and encrypted share.
//             // In an elliptic curve group, the operations are additive.
//             // Here, ephemeralKeys[i] and encryptedShares[i] are ECPoints.
//             ECPoint termU = ephemeralKeys[i].multiply(maskU).normalize();
//             ECPoint termV = encryptedShares[i].multiply(maskV).normalize();

//             // Aggregate the values using ECPoint addition.
//             U = U.add(termU).normalize();
//             V = V.add(termV).normalize();
//         }

//         NizkDlEqProof proof = NizkDlEqProofGenerator.generateProof(ctx, U, dealerPub, V, dealerKeyPair.getSecretKey());
//         // Verify the proof.
//         boolean valid = NizkDleqProofVerificator.verifyProof(ctx, U, dealerPub, V, proof);

//         return new DistributionResult(encryptedShares, proof, valid);
//     }
// }

package org.example.pvss;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

public class DHPVSS_Dist {

    /**
     * Container for the distribution result.
     * Contains the array of encrypted shares C_i and the DLEQ proof.
     */
    public static class DistributionResult {
        private final ECPoint[] encryptedShares;
        private final NizkDlEqProof dleqProof;

        public DistributionResult(ECPoint[] encryptedShares, NizkDlEqProof dleqProof) {
            this.encryptedShares = encryptedShares;
            this.dleqProof = dleqProof;
        }

        public ECPoint[] getEncryptedShares() {
            return encryptedShares;
        }

        public NizkDlEqProof getDleqProof() {
            return dleqProof;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("DistributionResult {\n");
            sb.append("  Encrypted Shares:\n");
            for (ECPoint share : encryptedShares) {
                sb.append("    ").append(share).append("\n");
            }
            sb.append("  DLEQ Proof: ").append(dleqProof).append("\n");
            sb.append("}");
            return sb.toString();
        }
    }

    /**
     * Distributes the dealer’s secret (as a group element S) by performing the
     * following steps:
     *
     * 1. Generate Shamir shares for the dealer’s secret.
     * Each share is computed as Aᵢ = S + m(αᵢ)·G, where m(X) is a random polynomial
     * with m(α₀)=0.
     *
     * 2. Encrypt each share using the dealer’s secret key sk_D and the
     * participant’s ephemeral key Eᵢ:
     * Cᵢ = Aᵢ + (sk_D · Eᵢ).
     *
     * 3. Derive a hash–chain polynomial (m*(X)) by hashing together:
     * – The dealer’s public key,
     * – The array of ephemeral keys (Eᵢ),
     * – The array of encrypted shares (Cᵢ).
     * Evaluate this polynomial at each participant’s evaluation point αᵢ to produce
     * scalars.
     * Multiply these by the dual-code coefficient vᵢ to obtain scrape scalars rᵢ.
     *
     * 4. Aggregate the contributions:
     * U = Σᵢ (rᵢ · Eᵢ) and V = Σᵢ (rᵢ · Cᵢ)
     * (using additive group operations on the elliptic curve).
     *
     * 5. Generate a DLEQ proof demonstrating that the dealer’s secret sk_D
     * satisfies the relation:
     * V = sk_D · U.
     *
     * @param ctx           The PVSS context (holds the EC group, evaluation points,
     *                      and dual-code coefficients).
     * @param ephemeralKeys An array of ephemeral public keys Eᵢ for the
     *                      participants.
     * @param dealerKeyPair The dealer’s key pair (contains sk_D and pk_D).
     * @param secret        The dealer’s secret as a group element S (typically S =
     *                      G·s).
     * @return A DistributionResult containing the encrypted shares and the DLEQ
     *         proof.
     */
    public static DistributionResult distribute(
            DhPvssContext ctx,
            ECPoint[] ephemeralKeys,
            DhKeyPair dealerKeyPair,
            ECPoint S) {

        int n = ctx.getNumParticipants();
        BigInteger p = ctx.getOrder(); // Prime modulus
        // Step 1: Generate Shamir shares.
        // Aᵢ = S + m(αᵢ)*G, with m(α₀)=0.
        // We assume that SSS_EC.generateSharesEC implements this.
        ECPoint[] shares = GShamir_Share.generateSharesEC(ctx, S);

        // Step 2: Encrypt shares with the dealer's secret key.
        // For each participant i, compute:
        // Cᵢ = Aᵢ + (sk_D * ephemeralKey_i)
        ECPoint[] encryptedShares = new ECPoint[n];
        for (int i = 0; i < n; i++) {
            ECPoint mask = ephemeralKeys[i].multiply(dealerKeyPair.getSecretKey()).normalize();
            encryptedShares[i] = shares[i].add(mask).normalize();
        }

        // Step 3: Derive a hash-chain polynomial from the dealer’s public key,
        // ephemeral keys, and encrypted shares.
        // The protocol requires computing:
        // m*(X) = H(pk_D, {Eᵢ}, {Cᵢ}) and then evaluating at each evaluation point.
        int numPolyCoeffs = n - ctx.getThreshold() - 1; // degree = n - t - 2, thus coeff count is n-t-1.
        BigInteger modulus = p;
        // Here, HashingTools.hashPointsToPoly must be updated to operate on ECPoints.
        BigInteger[] polyCoeffs = HashingTools.hashPointsToPoly(
                dealerKeyPair.getPublic(), // pk_D
                ephemeralKeys, // the ephemeral public keys, Eᵢ
                encryptedShares, // the encrypted shares, Cᵢ
                numPolyCoeffs,
                modulus);

        // Step 4: Evaluate the hash-derived polynomial at each evaluation point.
        BigInteger[] evaluations = new BigInteger[n + 1]; // evaluations indexed by the alpha values.
        BigInteger[] alphas = ctx.getAlphas();
        for (int i = 1; i <= n; i++) {
            evaluations[i] = EvaluationTools.evaluatePolynomial(polyCoeffs, alphas[i], modulus);
        }

        // Step 5: Aggregate contributions from each participant.
        // For each participant i, compute the "scrape" scalar r_i = evaluation(αᵢ) * vᵢ
        // mod modulus.
        ECPoint aggregateU = ctx.getGenerator().getCurve().getInfinity();
        ECPoint aggregateV = ctx.getGenerator().getCurve().getInfinity();
        BigInteger[] duals = ctx.getV();
        for (int i = 1; i <= n; i++) {
            BigInteger r_i = evaluations[i].multiply(duals[i - 1]).mod(modulus);
            // Aggregation: U = U + (Eᵢ * r_i), V = V + (Cᵢ * r_i)
            aggregateU = aggregateU.add(ephemeralKeys[i - 1].multiply(r_i)).normalize();
            aggregateV = aggregateV.add(encryptedShares[i - 1].multiply(r_i)).normalize();
        }

        // For debugging: you might print intermediate values here.
        System.out.println("Computed weighted aggregate U: " + aggregateU);
        System.out.println("Computed weighted aggregate V: " + aggregateV);

        // Step 6: Generate a DLEQ proof that shows V = sk_D * U.
        NizkDlEqProof dleqProof = NizkDlEqProof.generateProof(
                ctx,
                aggregateU, // h in the DLEQ proof (base U)
                dealerKeyPair.getPublic(), // x = pk_D = sk_D * G
                aggregateV, // y, computed aggregate V
                dealerKeyPair.getSecretKey()); // dealer’s secret sk_D

        // Optionally verify the proof (for debugging).
        boolean validProof = NizkDlEqProof.verifyProof(
                ctx,
                aggregateU,
                dealerKeyPair.getPublic(),
                aggregateV,
                dleqProof);
        System.out.println("DLEQ proof verification: " + validProof);

        return new DistributionResult(encryptedShares, dleqProof);
    }
}
