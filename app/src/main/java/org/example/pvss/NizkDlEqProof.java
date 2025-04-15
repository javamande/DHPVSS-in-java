package org.example.pvss;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;

public class NizkDlEqProof {
    private final BigInteger challenge;
    private final BigInteger response;

    public NizkDlEqProof(BigInteger challenge, BigInteger response) {
        this.challenge = challenge;
        this.response = response;
    }

    public BigInteger getChallenge() {
        return challenge;
    }

    public BigInteger getResponse() {
        return response;
    }

    @Override
    public String toString() {
        return "DleqProof{" +
                "challenge=" + challenge +
                ", response=" + response +
                '}';
    }

    private static final SecureRandom random = new SecureRandom();

    /**
     * Generates a DLEQ proof for the elliptic curve relation:
     *
     * Given:
     * x = [α]G and y = [α]h,
     *
     * this proof shows knowledge of the secret scalar α.
     *
     * In the PVSS distribution:
     * - G is the group generator.
     * - h is the secondary base (for example, the aggregated commitment U).
     * - x is the dealer’s public key (computed as [α]G).
     * - y is the value computed as [α]h (e.g. from the aggregation of encrypted
     * shares).
     * - α is the dealer’s secret key (skD).
     *
     * The proof is constructed as follows:
     * 1. Choose a random nonce w ∈ [1, q−1], where q is the subgroup order.
     * 2. Compute the commitments:
     * a1 = [w]G, and a2 = [w]h.
     * 3. Compute the hash H = Hash(G, x, h, y, a1, a2) (using a fixed-length
     * encoding),
     * then reduce it modulo q.
     * 4. Use H as a seed to a deterministic PRNG to “draw” a challenge e ∈ [1,
     * q−1].
     * 5. Compute the response: z = w − e·α mod q.
     *
     * @param ctx   the PVSS context containing the group parameters.
     * @param h     the secondary base (an ECPoint, e.g. U).
     * @param x     the public value [α]G (e.g. dealer’s public key).
     * @param y     the second public value [α]h.
     * @param alpha the secret scalar (e.g. the dealer’s secret skD).
     * @return a NizkDlEqProof object containing the challenge e and response z.
     */
    public static NizkDlEqProof generateProof(DhPvssContext ctx, ECPoint h, ECPoint x, ECPoint y, BigInteger alpha) {
        // Obtain the subgroup order q (for secp256r1, typically this is defined in the
        // EC domain parameters)
        BigInteger q = ctx.getGroupParameters().getN();
        ECPoint G = ctx.getGenerator();

        // Step 1. Choose random nonce w ∈ [1, q−1]
        BigInteger w;
        do {
            w = new BigInteger(q.bitLength(), random);
        } while (w.compareTo(BigInteger.ZERO) <= 0 || w.compareTo(q) >= 0);

        // Step 2. Compute commitments using elliptic curve scalar multiplication:
        // a1 = [w]G and a2 = [w]h.
        ECPoint a1 = G.multiply(w).normalize();
        ECPoint a2 = h.multiply(w).normalize();
        System.out.println("DLEQ Proof Generation:");
        System.out.println("  Nonce w: " + w);
        System.out.println("  Commitment a1 ([w]G): " + a1);
        System.out.println("  Commitment a2 ([w]h): " + a2);

        // Step 3. Compute the hash H = Hash(G, x, h, y, a1, a2), and reduce modulo q.
        // (Ensure that your ingHashingToolshashElements method accepts ECPoints and
        // returns a
        // BigInteger.)
        BigInteger hashValue = HashingTools.hashElements(ctx, G, x, h, y, a1, a2).mod(q);
        System.out.println("  Hash value H (mod q): " + hashValue);

        // Step 4. Use the hash as a seed for a deterministic PRNG to generate the
        // challenge e.
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
        } while (e.compareTo(BigInteger.ZERO) == 0 || e.compareTo(q) >= 0);
        System.out.println("  Challenge e (from PRG): " + e);

        // Step 5. Compute the response: z = w - e * α mod q.
        BigInteger z = w.subtract(e.multiply(alpha)).mod(q);
        System.out.println("  Response z: " + z);

        return new NizkDlEqProof(e, z);
    }

    /**
     * Verifies a DLEQ proof for the relation:
     *
     * Given that x = [α]G and y = [α]h, the proof demonstrates that the same scalar
     * α was used.
     *
     * Verification steps:
     * 1. Recompute a1' = [z]G + [e]x, and a2' = [z]h + [e]y.
     * 2. Compute H' = Hash(G, x, h, y, a1', a2') mod q.
     * 3. Use H' as the seed for a deterministic PRNG to obtain challenge e'.
     * 4. The proof verifies if e' equals the challenge in the proof.
     *
     * @param ctx   the PVSS context containing group parameters.
     * @param h     the second base (ECPoint).
     * @param x     the public value [α]G.
     * @param y     the public value [α]h.
     * @param proof the DLEQ proof containing the challenge e and response z.
     * @return true if the proof verifies; false otherwise.
     */
    public static boolean verifyProof(DhPvssContext ctx, ECPoint h, ECPoint x, ECPoint y, NizkDlEqProof proof) {
        BigInteger q = ctx.getGroupParameters().getN();
        ECPoint G = ctx.getGenerator();

        System.out.println("DLEQ Proof Verification:");
        System.out.println("  Received proof: e = " + proof.getChallenge() + ", z = " + proof.getResponse());

        // Step 1. Recompute commitments:
        // a1' = [z]G + [e]x and a2' = [z]h + [e]y.
        ECPoint a1Prime = G.multiply(proof.getResponse()).add(x.multiply(proof.getChallenge())).normalize();
        ECPoint a2Prime = h.multiply(proof.getResponse()).add(y.multiply(proof.getChallenge())).normalize();
        System.out.println("  Recomputed commitment a1': " + a1Prime);
        System.out.println("  Recomputed commitment a2': " + a2Prime);

        // Step 2. Compute the verification hash H' = Hash(G, x, h, y, a1', a2') mod q.
        BigInteger hashValue = HashingTools.hashElements(ctx, G, x, h, y, a1Prime, a2Prime).mod(q);
        System.out.println("  Verification hash value H' (mod q): " + hashValue);

        // Step 3. Seed a PRNG with H' and generate the challenge e'.
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

        // Step 4. The proof is valid if the computed challenge matches the one in the
        // proof.
        boolean isValid = computedE.equals(proof.getChallenge());
        System.out.println("  DLEQ proof verification result: " + isValid);
        return isValid;
    }
}
