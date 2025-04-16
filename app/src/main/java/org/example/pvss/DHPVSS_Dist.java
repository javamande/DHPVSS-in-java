package org.example.pvss;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

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
            EphemeralKeyPublic[] epksWithProof,
            DhKeyPair dealerKeyPair,
            ECPoint S) {
        // 1) Verify each ephemeral key proof
        for (EphemeralKeyPublic ek : epksWithProof) {
            try {
                if (!NizkDlProof.verifyProof(ctx, ek.getPublicKey(), ek.getProof())) {
                    throw new IllegalArgumentException("Invalid ephemeral-key proof: " + ek);
                }
            } catch (NoSuchAlgorithmException e) {
                // wrap checked exception
                throw new RuntimeException("Hash algorithm unavailable", e);
            }
        }

        // 2) Extract the raw ECPoints (Public Keys)
        ECPoint[] E = new ECPoint[epksWithProof.length];
        for (int i = 0; i < E.length; i++) {
            E[i] = epksWithProof[i].getPublicKey();
        }

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
            ECPoint mask = E[i].multiply(dealerKeyPair.getSecretKey()).normalize();
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
                E, // the ephemeral public keys, Eᵢ
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
            aggregateU = aggregateU.add(E[i - 1].multiply(r_i)).normalize();
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

    public static void main(String[] args) throws NoSuchAlgorithmException {
        GroupGenerator.GroupParameters gp = GroupGenerator.generateGroup();
        int t = 10;
        int n = 20;
        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(gp, t, n);

        // Dealer key‐pair + secret point S = G·s
        DhKeyPair dealer = DhKeyPair.generate(ctx);
        BigInteger s = dealer.getSecretKey().mod(ctx.getOrder());
        ECPoint S = ctx.getGenerator().multiply(s);

        EphemeralKeyPublic[] epks = new EphemeralKeyPublic[n];
        for (int i = 0; i < n; i++) {
            DhKeyPair kp = DhKeyPair.generate(ctx);
            // generate a DL proof for the ephemeral key
            NizkDlProof proof = NizkDlProof.generateProof(ctx, kp);
            epks[i] = new EphemeralKeyPublic(kp.getPublic(), proof);
        }

        DHPVSS_Dist.distribute(ctx, epks, dealer, S);

    }
}
