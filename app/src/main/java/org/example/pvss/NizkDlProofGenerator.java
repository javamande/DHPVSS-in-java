package org.example.pvss;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import org.bouncycastle.math.ec.ECPoint;

public class NizkDlProofGenerator {
    // A global SecureRandom instance for general randomness.
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
        BigInteger hashValue = Hash.hashElements(ctx, pub, A).mod(q);
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

}
