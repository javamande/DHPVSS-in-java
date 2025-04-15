package org.example.pvss;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;

/**
 * A simple representation of a non-interactive zero-knowledge (NIZK) proof
 * for a discrete logarithm relation. Typically this proof contains two values:
 * a challenge and a response.
 */
public class NizkDlProof {
    private final BigInteger challenge; // private for anonomity/safety
    // Final = once the field is assigned a value (typically in the constructor), it
    // cannot be changed.
    // private final ensures that once the proof is constructed, its values remain
    // constant
    private final BigInteger response; // private for anonomity/safety

    /**
     * Constructs a NizkDlProof with the given challenge and response.
     *
     * @param challenge the challenge value (often computed via a hash) e
     * @param response  the response value computed as z = r - e * x mod order
     */

    // Constructor for NizkDlProof.
    public NizkDlProof(BigInteger challenge, BigInteger response) {
        this.challenge = challenge;
        this.response = response;
    }

    public BigInteger getChallenge() {
        return challenge;
    }

    public BigInteger getResponse() {
        return response;
    }

    @Override // best practice to annotate methods that are intended to override a method from
              // a superclass.
    public String toString() {
        return "NizkDlProof{" +
                "challenge=" + challenge +
                ", response=" + response +
                '}';
    }

    private static final SecureRandom random = new SecureRandom();

    /**
     * Generates a non‑interactive zero knowledge (NIZK) proof (via Fiat‑Shamir) for
     * the
     * discrete logarithm relation on an elliptic curve.
     *
     * The proof shows knowledge of a secret scalar x such that:
     * pub = g · x,
     * where g is the group generator and pub is the public key (an ECPoint).
     *
     * The process is as follows:
     * 1. Sample a random nonce r (1 ≤ r < q) from Z_q.
     * 2. Compute the commitment A = r · g.
     * 3. Compute a hash over (g, pub, A) to obtain a seed value, reduce it modulo
     * q,
     * and use it to deterministically generate a challenge e.
     * 4. Compute the response: z = r – e · x (mod q).
     *
     * @param ctx     the PVSS context containing elliptic curve parameters.
     * @param keyPair the DhKeyPair containing the secret key x and public key pub.
     * @return a NizkDlProof object containing the challenge e and response z.
     * @throws NoSuchAlgorithmException if the specified PRNG algorithm is not
     *                                  available.
     */
    public static NizkDlProof generateProof(DhPvssContext ctx, DhKeyPair keyPair) throws NoSuchAlgorithmException {
        // Retrieve the subgroup order q (for secp256r1, this is a fixed value).
        BigInteger q = ctx.getGroupParameters().getN();
        // Retrieve the generator point g.
        ECPoint g = ctx.getGenerator();
        // Retrieve the public key and secret scalar x from the key pair.
        ECPoint pub = keyPair.getPublic();
        BigInteger x = keyPair.getSecretKey();

        // Step 1: Generate a random nonce r in [1, q-1].
        BigInteger r;
        do {
            r = new BigInteger(q.bitLength(), random);
        } while (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(q) >= 0);
        System.out.println("DEBUG: Nonce r: " + r);

        // Step 2: Compute the commitment A = r · g.
        ECPoint A = g.multiply(r);
        System.out.println("DEBUG: Commitment A: " + A);

        // Step 3: Compute the challenge seed by hashing (g, pub, A) using the
        // EC-compatible hash.
        BigInteger hashValue = HashingTools.hashElements(ctx, pub, A).mod(q);
        System.out.println("DEBUG: Hash value (mod q): " + hashValue);

        // Use the hash value as seed for a deterministic PRNG (SHA1PRNG) to obtain the
        // challenge.
        SecureRandom prg = SecureRandom.getInstance("SHA1PRNG");
        prg.setSeed(hashValue.toByteArray());
        BigInteger e;
        do {
            e = new BigInteger(q.bitLength(), prg);
        } while (e.compareTo(BigInteger.ZERO) <= 0 || e.compareTo(q) >= 0);
        System.out.println("DEBUG: Challenge e from PRG: " + e);

        // Step 4: Compute the response: z = r - e * x mod q.
        BigInteger z = r.subtract(e.multiply(x)).mod(q);
        System.out.println("DEBUG: Response z: " + z);

        return new NizkDlProof(e, z);
    }

    /**
     * Verifies a NIZK proof for the discrete logarithm relation.
     *
     * Given g (the generator), pub = g · x, and a proof (e, z), the verifier
     * computes:
     * A' = z · g + e · pub.
     * Then, it hashes (g, pub, A') and uses the result (seeded into a PRNG) to
     * generate a challenge e'.
     * The proof is accepted if e' equals the challenge from the proof.
     *
     * @param ctx   the PVSS context containing elliptic curve parameters.
     * @param pub   the public key as an ECPoint.
     * @param proof the NizkDlProof containing the challenge and response.
     * @return true if the proof is valid, false otherwise.
     * @throws NoSuchAlgorithmException if the PRNG algorithm is not available.
     */
    public static boolean verifyProof(DhPvssContext ctx, ECPoint pub, NizkDlProof proof)
            throws NoSuchAlgorithmException {
        // Retrieve subgroup order q and generator g.
        BigInteger q = ctx.getGroupParameters().getN();
        ECPoint g = ctx.getGenerator();

        // Recompute A' = g·z + pub·e (elliptic curve addition and scalar
        // multiplication).
        // Note: In additive notation for elliptic curves, this is the correct formula.
        ECPoint APrime = g.multiply(proof.getResponse()).add(pub.multiply(proof.getChallenge()));
        System.out.println("DEBUG: Recomputed commitment A': " + APrime);

        // Recompute the hash seed based on (g, pub, A').
        BigInteger computedHash = HashingTools.hashElements(ctx, pub, APrime).mod(q);
        System.out.println("DEBUG: Recomputed hash value (mod q): " + computedHash);

        // Use the computed hash as seed for a deterministic PRNG to generate challenge
        // e'.
        SecureRandom prg = SecureRandom.getInstance("SHA1PRNG");
        prg.setSeed(computedHash.toByteArray());
        BigInteger computedE;
        do {
            computedE = new BigInteger(q.bitLength(), prg);
        } while (computedE.compareTo(BigInteger.ZERO) <= 0 || computedE.compareTo(q) >= 0);
        System.out.println("DEBUG: Computed challenge e' from PRG: " + computedE);

        // The proof is valid if the computed challenge equals the challenge in the
        // proof.
        boolean isValid = computedE.equals(proof.getChallenge());
        System.out.println("DEBUG: NIZK DL proof verification result: " + isValid);
        return isValid;
    }

}
