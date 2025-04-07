package org.example.pvss;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * NizkDlEqProofGenerator implements a non-interactive zero-knowledge proof
 * (using Fiat-Shamir)
 * for the discrete logarithm equality (DLEQ) relation.
 *
 * This proof is used in two primary places in our PVSS protocol:
 *
 * 1. In the distribution phase, to prove that the dealer's secret key (skD) was
 * used to generate
 * the dealer's public key and the encrypted shares. Formally, it proves that:
 * - pkD = g^(skD) mod p, and
 * - V = h^(skD) mod p,
 * for given bases g and h. In our PVSS distribution, h is computed as the
 * weighted sum U of
 * the commitment keys, and V as the weighted sum of the encrypted shares.
 *
 * 2. In the decryption phase (DHPVSS.DecShare), to prove that a participant
 * used the same secret key (sk)
 * to correctly decrypt their share. The proof is analogous.
 *
 * The protocol works as follows:
 *
 * Let the group parameters be (p, g) and let h be a second base in Z_p*. For a
 * secret exponent α:
 *
 * - x = g^α mod p and y = h^α mod p.
 *
 * The prover does:
 * 1. Chooses a random nonce w ∈ Z_q (where q is the subgroup order).
 * 2. Computes commitments:
 * a1 = g^w mod p, and a2 = h^w mod p.
 * 3. Computes a hash H = Hash(g, x, h, y, a1, a2) and reduces it modulo q.
 * 4. Uses H as a seed to a deterministic PRNG (e.g. SHA1PRNG) and draws a
 * challenge e ∈ Z_q.
 * 5. Computes the response: z = w - e·α mod q.
 *
 * The proof is the pair (e, z).
 *
 * The verifier recomputes:
 * - a1' = g^z * x^e mod p,
 * - a2' = h^z * y^e mod p,
 * then computes H' = Hash(g, x, h, y, a1', a2') mod q, seeds a PRNG with H',
 * draws a challenge e',
 * and accepts if e' equals the challenge provided in the proof.
 */
public class NizkDlEqProofGenerator {
    // A global SecureRandom instance for general randomness.
    private static final SecureRandom random = new SecureRandom();

    /**
     * Generates a DLEQ proof for the relation:
     *
     * x = g^α mod p and y = h^α mod p
     *
     * This proof shows that the same exponent α was used for both computations.
     * In the PVSS distribution, this is used to prove that the dealer's secret key
     * (skD)
     * was used consistently in encrypting shares. Similarly, it can be used for
     * share decryption.
     * 
     * * In the PVSS distribution context:
     * - g is the group generator,
     * - h is the weighted aggregate U of the commitment keys,
     * - x is the dealer’s public key (computed as g^(sk_D)),
     * - y is the weighted aggregate V of the encrypted shares,
     * - α is the dealer’s secret key (sk_D).
     *
     * @param ctx   The PVSS context containing group parameters (p, g, and subgroup
     *              order q).
     * @param h     The second base. In distribution, h is typically the computed
     *              weighted sum U.
     *              In decryption, h might be a different value related to the
     *              decryption process.
     * @param x     The public value computed as x = g^α mod p (e.g. dealer's public
     *              key pkD).
     * @param y     The second public value computed as y = h^α mod p (e.g. a value
     *              derived from encrypted shares or decryption).
     * @param alpha The secret exponent (e.g., skD in distribution or sk in
     *              decryption).
     * @return A NizkDlEqProof object containing the challenge e and response z.
     */
    public static NizkDlEqProof generateProof(DhPvssContext ctx,
            BigInteger h,
            BigInteger x,
            BigInteger y,
            BigInteger alpha) {
        BigInteger p = ctx.getOrder();
        BigInteger q = ctx.getGroupParameters().getSubgroupOrder(); // q = (p-1)/2 typically.
        BigInteger g = ctx.getGenerator();

        // Step 1: Choose a random nonce w from 1 to q-1.
        BigInteger w;
        do {
            w = new BigInteger(q.bitLength(), random);
        } while (w.compareTo(BigInteger.ZERO) <= 0 || w.compareTo(q) >= 0);

        // Step 2: Compute the commitments:
        // a1 = g^w mod p, and a2 = h^w mod p.
        BigInteger a1 = g.modPow(w, p);
        BigInteger a2 = h.modPow(w, p);
        System.out.println("DLEQ Proof Generation:");
        System.out.println("  Nonce w: " + w);
        System.out.println("  Commitment a1 (g^w mod p): " + a1);
        System.out.println("  Commitment a2 (h^w mod p): " + a2);

        // Step 3: Compute the hash H = Hash(g, x, h, y, a1, a2) mod q.
        // The hash function must use fixed-length encoding for consistency.
        BigInteger hashValue = Hash.hashElements(ctx, x, h, y, a1, a2).mod(q);
        System.out.println("  Hash value H (mod q): " + hashValue);

        // Step 4: Use the hash as a seed for a deterministic PRNG (e.g. SHA1PRNG) to
        // obtain the challenge.
        SecureRandom prg;
        try {
            prg = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("SHA1PRNG not available", ex);
        }
        prg.setSeed(hashValue.toByteArray());
        BigInteger e;
        do {
            e = new BigInteger(q.bitLength(), prg);
        } while (e.compareTo(BigInteger.ZERO) <= 0 || e.compareTo(q) >= 0);
        System.out.println("  Challenge e (from PRG): " + e);

        // Step 5: Compute the response: z = w - e * α mod q.
        BigInteger z = w.subtract(e.multiply(alpha)).mod(q);
        System.out.println("  Response z: " + z);
        System.err.println(" ");
        return new NizkDlEqProof(e, z);
    }

    /**
     * Verifies a DLEQ proof.
     *
     * This method proves the following relation:
     *
     * Given group parameters (p, g) and a second base h, and given public values:
     * x = g^α mod p and y = h^α mod p,
     *
     * the DLEQ proof proves that the same exponent α (which may be the dealer's
     * secret skD)
     * was used to compute both x and y.
     *
     * In the PVSS distribution protocol, this is used to prove that:
     * - The dealer’s public key (x) is computed as g^(skD) mod p.
     * - The encrypted shares have been processed so that V (here, y) equals U^(skD)
     * mod p,
     * where U is derived from the commitment keys.
     *
     * Proof Generation (for reference):
     * - The prover chooses a random nonce w and computes:
     * a1 = g^w mod p,
     * a2 = h^w mod p.
     * - Then, a challenge e is derived (via a PRG seeded with H(g, x, h, y, a1, a2)
     * mod q),
     * and the response is computed as:
     * z = w - e * α mod q.
     *
     * Verification:
     * - The verifier recomputes:
     * a1' = g^z * x^e mod p,
     * a2' = h^z * y^e mod p.
     * If the proof is valid, then a1' should equal a1 and a2' should equal a2.
     * - The verifier then computes a hash H' = H(g, x, h, y, a1', a2') mod q, seeds
     * a deterministic
     * PRNG with H', and draws a challenge e'. The proof is accepted if e' equals
     * the challenge e in the proof.
     *
     * @param ctx   The PVSS context containing group parameters.
     * @param h     The second base (for example, U in distribution).
     * @param x     The public value computed as x = g^α mod p (e.g., the dealer's
     *              public key).
     * @param y     The second public value computed as y = h^α mod p (e.g., V in
     *              distribution).
     * @param proof The DLEQ proof containing the challenge e and response z.
     * @return true if the proof verifies; false otherwise.
     */
    public static boolean verifyProof(DhPvssContext ctx,
            BigInteger h,
            BigInteger x,
            BigInteger y,
            NizkDlEqProof proof) {
        BigInteger p = ctx.getOrder();
        BigInteger q = ctx.getGroupParameters().getSubgroupOrder();
        BigInteger g = ctx.getGenerator();

        System.out.println("DLEQ Proof Verification:");
        System.out.println("  Received proof: e = " + proof.getChallenge() + ", z = " + proof.getResponse());

        // Recompute a1' = g^z * x^e mod p.
        // Intuition: Since x = g^α, and z = w - e·α, then:
        // a1' = g^(w - e·α) * (g^α)^e = g^(w - e·α + e·α) = g^w, which equals a1.
        BigInteger a1Prime = g.modPow(proof.getResponse(), p)
                .multiply(x.modPow(proof.getChallenge(), p))
                .mod(p);
        // Recompute a2' = h^z * y^e mod p.
        // Similarly, since y = h^α, a2' should equal h^w.
        BigInteger a2Prime = h.modPow(proof.getResponse(), p)
                .multiply(y.modPow(proof.getChallenge(), p))
                .mod(p);
        System.out.println("  Recomputed commitment a1': " + a1Prime);
        System.out.println("  Recomputed commitment a2': " + a2Prime);

        // Compute the verification hash: H' = H(g, x, h, y, a1', a2') mod q.
        // This hash should be identical to the hash used during proof generation if a1'
        // and a2'
        // equal the original commitments.
        BigInteger hashValue = Hash.hashElements(ctx, x, h, y, a1Prime, a2Prime).mod(q);
        System.out.println("  Verification hash value H' (mod q): " + hashValue);

        // Use the hash value as seed for a deterministic PRNG to derive the challenge.
        SecureRandom prg;
        try {
            prg = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("SHA1PRNG not available", ex);
        }
        prg.setSeed(hashValue.toByteArray());

        BigInteger computedE;
        do {
            computedE = new BigInteger(q.bitLength(), prg);
        } while (computedE.compareTo(BigInteger.ZERO) <= 0 || computedE.compareTo(q) >= 0);
        System.out.println("  Computed challenge e' from PRG: " + computedE);

        boolean isValid = computedE.equals(proof.getChallenge());
        System.out.println("  DLEQ proof verification result: " + isValid);
        return isValid;
    }
}
