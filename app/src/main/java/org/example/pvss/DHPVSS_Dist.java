package org.example.pvss;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.math.ec.ECPoint;

public class DHPVSS_Dist {

    /**
     * Holds the output of the distribution phase:
     * • Cᵢ ∈ 𝔾: encrypted shares for i=1…n
     * • Proof that ⟨U, pk_D⟩ = V under exponent sk_D (i.e. V = sk_D·U)
     */
    public static class DistributionResult {
        private final ECPoint[] C; // Cᵢ = Aᵢ + sk_D·Eᵢ
        private final NizkDlEqProof πD; // DLEQ proof: log_U(V) = log_G(pk_D)

        public DistributionResult(ECPoint[] C, NizkDlEqProof πD) {
            this.C = C;
            this.πD = πD;
        }

        /** @return the array {C₁,…,Cₙ} of encrypted shares */
        public ECPoint[] getEncryptedShares() {
            return C;
        }

        /** @return the DLEQ proof πD that V = sk_D·U */
        public NizkDlEqProof getDleqProof() {
            return πD;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder("DistributionResult {\n");
            sb.append("  Encrypted Shares Cᵢ:\n");
            for (ECPoint Ci : C) {
                sb.append("    ").append(Ci).append("\n");
            }
            sb.append("  DLEQ Proof πD: ").append(πD).append("\n");
            sb.append("}");
            return sb.toString();
        }
    }

    /**
     * Perform DHPVSS distribution of a secret point S ∈ 𝔾 across n parties:
     *
     * 1) Verify each ephemeral key Eᵢ came with a valid NIZK proof.
     * 2) Compute Shamir shares Aᵢ = S + m(αᵢ)·G.
     * 3) Encrypt: Cᵢ = Aᵢ + sk_D·Eᵢ for i = 1…n.
     * 4) Build a hash‑derived polynomial m* and evaluate at each αᵢ to get eᵢ,
     * then multiply by dual–code weight vᵢ to obtain rᵢ.
     * 5) Compute U = Σᵢ rᵢ·Eᵢ and V = Σᵢ rᵢ·Cᵢ.
     * 6) Output {Cᵢ} and a DLEQ proof that V = sk_D·U.
     *
     * @param ctx  DHPVSS context (generator G, {α₀…αₙ}, {v₁…vₙ}, threshold t)
     * @param epks array of EphemeralKeyPublic (Eᵢ plus its proof)
     * @param dk   dealer’s DhKeyPair containing sk_D and pk_D=G·sk_D
     * @param S    the dealer’s secret point (S = G·s)
     */
    public static DistributionResult distribute(
            DhPvssContext ctx,
            EphemeralKeyPublic[] epks,
            DhKeyPair dk,
            ECPoint S) {

        // 1) verify each Eᵢ proof
        for (EphemeralKeyPublic e : epks) {
            try {
                if (!NizkDlProof.verifyProof(ctx, e.getPublicKey(), e.getProof())) {
                    throw new IllegalArgumentException("Invalid proof for ephemeral key: " + e);
                }
            } catch (NoSuchAlgorithmException ex) {
                throw new RuntimeException("PRG unavailable", ex);
            }
        }

        // extract raw Eᵢ
        int n = ctx.getNumParticipants();
        ECPoint[] E = new ECPoint[n];
        for (int i = 0; i < n; i++) {
            E[i] = epks[i].getPublicKey();
        }

        // 2) compute Shamir shares Aᵢ = S + m(αᵢ)·G
        ECPoint[] A = GShamir_Share.generateSharesEC(ctx, S);

        // 3) encrypt shares: Cᵢ = Aᵢ + sk_D·Eᵢ
        BigInteger skD = dk.getSecretKey();
        ECPoint[] C = new ECPoint[n];
        for (int i = 0; i < n; i++) {
            ECPoint mask = E[i].multiply(skD).normalize();
            C[i] = A[i].add(mask).normalize();
        }

        // 4) derive hash‑chain polynomial m*(X):
        // hash(pk_D, {Eᵢ}, {Cᵢ}) → poly coeffs of degree ≤ (n−t−2)
        int deg = n - ctx.getThreshold() - 2;
        BigInteger p = ctx.getOrder();
        BigInteger[] mStar = HashingTools.hashPointsToPoly(
                dk.getPublic(), E, C, deg, p);

        // evaluate m* at each αᵢ → eᵢ, then rᵢ = vᵢ·eᵢ mod p
        BigInteger[] α = ctx.getAlphas();
        BigInteger[] v = ctx.getV();
        ECPoint U = ctx.getGenerator().getCurve().getInfinity();
        ECPoint V = ctx.getGenerator().getCurve().getInfinity();
        for (int i = 1; i <= n; i++) {
            BigInteger ei = EvaluationTools.evaluatePolynomial(mStar, α[i], p);
            BigInteger ri = ei.multiply(v[i - 1]).mod(p);
            U = U.add(E[i - 1].multiply(ri)).normalize();
            V = V.add(C[i - 1].multiply(ri)).normalize();
        }

        // 5) prove V = sk_D·U via DLEQ
        NizkDlEqProof πD = NizkDlEqProof.generateProof(
                ctx, U, dk.getPublic(), V, skD);

        // (optional) self‑check
        System.out.println("U = " + U);
        System.out.println("V = " + V);
        System.out.println("DLEQ ok? " +
                NizkDlEqProof.verifyProof(ctx, U, dk.getPublic(), V, πD));

        return new DistributionResult(C, πD);
    }
}
