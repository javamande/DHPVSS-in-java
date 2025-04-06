// package org.example.pvss;

// import java.math.BigInteger;
// import java.security.SecureRandom;

// public class SSS {

// /**
// * Generates shares for the dealer using Shamir secret sharing in the
// * multiplicative formulation.
// *
// * The dealer’s polynomial is defined as:
// * m(X) = a₀ + a₁ * X + a₂ * X^2 + ... + a_t * X^t (mod p)
// * where a₀ is set to 0 (so m(0)=0). This ensures that the “masking” part
// * cancels
// * when we reconstruct the secret.
// *
// * The share for participant i (with evaluation point αᵢ) is computed as:
// * Aᵢ = S + [G^(m(αᵢ))] mod p,
// * where S is the dealer’s secret (encoded as a group element, e.g. S = G^s).
// *
// * @param ctx the DhPvssContext holding public parameters (prime modulus p,
// * generator G, evaluation points, etc.)
// * @param secret the dealer’s secret as a group element (for example, S = G^s
// * mod p)
// * @return an array of shares A_i for participants i = 1, …, n.
// */
// public static BigInteger[] generateShares(DhPvssContext ctx, BigInteger
// secret) {
// int n = ctx.getNumParticipants(); // total number of participants
// int t = ctx.getThreshold(); // threshold; polynomial degree is t (so there
// are t+1 coefficients)
// BigInteger primeOrder = ctx.getOrder(); // prime modulus p
// BigInteger[] alphas = ctx.getAlphas(); // Evaluation points: α₀, α₁, …, αₙ

// // --- Step 1: Generate polynomial coefficients ---
// // We want a polynomial m(X) of degree t with m(0) = 0.
// // We explicitly set the constant coefficient to 0.
// BigInteger[] coeffs = new BigInteger[t + 1];
// coeffs[0] = BigInteger.ZERO; // This forces m(0) = 0.
// SecureRandom random = new SecureRandom();
// // For j = 1 to t, generate random coefficients a_j in Z_p.
// for (int j = 1; j <= t; j++) {
// coeffs[j] = new BigInteger(primeOrder.bitLength(), random).mod(primeOrder);
// }

// // --- Step 2: Evaluate the polynomial m(X) at each evaluation point ---
// // For each participant i (i = 1,..., n), we evaluate m(α_i) as:
// // m(α_i) = a₀ + a₁ * (α_i)^1 + a₂ * (α_i)^2 + ... + a_t * (α_i)^t mod p.
// // Since a₀ = 0, this simplifies to the sum from j = 1 to t.
// BigInteger[] shares = new BigInteger[n];
// for (int i = 1; i <= n; i++) {
// BigInteger x = alphas[i]; // Evaluation point α_i.
// BigInteger mEval = BigInteger.ZERO; // This will hold m(α_i).
// for (int j = 0; j <= t; j++) { // Loop from j=0 to t.
// // For j = 0, term = a₀ * (α_i)^0 = 0 (since a₀ = 0).
// // For j >= 1, term = a_j * (α_i)^j mod p.
// BigInteger term = coeffs[j].multiply(x.modPow(BigInteger.valueOf(j),
// primeOrder)).mod(primeOrder);
// mEval = mEval.add(term).mod(primeOrder);
// }

// // --- Step 3: Compute the masked part ---
// // In the multiplicative formulation, we encode the random masking as:
// // maskedPart = G^(mEval) mod p.
// // This is analogous to multiplying G by itself mEval times.
// BigInteger maskedPart = ctx.getGenerator().modPow(mEval, primeOrder);

// // --- Step 4: Form the share ---
// // The share for participant i is then defined as:
// // A_i = S + maskedPart mod p.
// // In additive notation, this means we add the secret (a group element) to
// the
// // masked part.
// shares[i - 1] = secret.add(maskedPart).mod(primeOrder);
// }
// return shares;
// }

// /**
// * Reconstructs the dealer's secret S from the shares using standard Lagrange
// * interpolation.
// *
// * The shares are assumed to be computed as:
// * A_i = S + [m(α_i) · G] mod p,
// * where m(α₀)=0 (with α₀ taken as the designated evaluation point, typically
// * 0).
// *
// * The reconstruction computes:
// * S' = Σ_{i in I} λ_i * A_i mod p,
// * where the Lagrange coefficient for share i is:
// * λ_i = ∏_{j in I, j ≠ i} ((α₀ - α_j) / (α_i - α_j)) mod p.
// *
// * If the random part cancels (i.e. Σ λ_i * m(α_i) = 0), then S' should equal
// S.
// *
// * @param ctx the PVSS context (provides p and evaluation points)
// * @param shares an array of shares A_i for a chosen subset I ⊆ {1,…, n}
// * @param indices an array of indices corresponding to the shares (values in
// * {1,…, n})
// * @return the reconstructed secret S (a group element in Z_p)
// */
// public static BigInteger reconstructSecret(DhPvssContext ctx, BigInteger[]
// shares, int[] indices) {
// if (shares.length != indices.length) {
// throw new IllegalArgumentException("Number of shares must equal number of
// indices.");
// }
// BigInteger p = ctx.getOrder();
// BigInteger[] alphas = ctx.getAlphas();
// // Here we interpolate at x = 0, so we set the reference point to 0.
// BigInteger x0 = BigInteger.ZERO;

// BigInteger S_reconstructed = BigInteger.ZERO;

// for (int i = 0; i < shares.length; i++) {
// int idx = indices[i]; // Evaluation point for share A_i (should be in {1,...,
// n})
// BigInteger lambda = BigInteger.ONE;
// for (int j = 0; j < shares.length; j++) {
// if (i == j)
// continue;
// int idx_j = indices[j];
// // Compute Lagrange coefficient λ_i:
// // λ_i = ∏_{j ≠ i} ((x0 - α_j) / (α_i - α_j)) mod p.
// // Here x0 = 0.
// BigInteger numerator = x0.subtract(alphas[idx_j]).mod(p);
// BigInteger denominator = alphas[idx].subtract(alphas[idx_j]).mod(p);
// BigInteger invDenom = denominator.modInverse(p);
// lambda = lambda.multiply(numerator.multiply(invDenom)).mod(p);
// }
// System.out.println("Lagrange coefficient for share at index " + idx + " = " +
// lambda);
// S_reconstructed = S_reconstructed.add(shares[i].multiply(lambda)).mod(p);
// }
// return S_reconstructed;
// }

// }
