package org.example.pvss;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;

public class NizkDLProofVerificator {
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
        BigInteger computedHash = Hash.hashElements(ctx, pub, APrime).mod(q);
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
