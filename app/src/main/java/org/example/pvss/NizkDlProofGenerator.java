package org.example.pvss;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

//
public class NizkDlProofGenerator {
    private static final SecureRandom random = new SecureRandom();

    /**
     * Generates a NIZK proof for the discrete logarithm relation:
     * proves knowledge of x such that pub = g^x mod p.
     *
     * @param group   the group parameters (p, g, and subgroup order).
     * @param keyPair the DhKeyPair containing the secret key x and public key pub.
     * @return a NizkDlProof containing the challenge and the response.
     * 
     */
    public static NizkDlProof generateProof(DhPvssContext ctx, DhKeyPair keyPair) throws NoSuchAlgorithmException {
        BigInteger p = ctx.getOrder();
        BigInteger q = ctx.getGroupParameters().getSubgroupOrder(); // subgroup order
        BigInteger g = ctx.getGenerator();
        BigInteger secretK = keyPair.getSecretKey();
        // Step 1: Generate random nonce r (in the range [1, order-1])
        BigInteger r;
        do {
            r = new BigInteger(q.bitLength(), random);
        } while (r.compareTo(BigInteger.ZERO) == 0 || r.compareTo(q) >= 0);
        System.out.println("DEBUG: Nonce r: " + r);
        // Step 2: Compute commitment A = g^r mod p
        BigInteger A = g.modPow(r, p);
        System.out.println("DEBUG: Commitment A: " + A);
        // Step 3: Compute challenge hashvalue = Hash(g, pub, A) mod order.
        BigInteger hashvalue = Hash.hashElements(ctx, keyPair.getPublic(), A).mod(q);

        System.out.println("DEBUG: Hash value (mod q): " + hashvalue);

        SecureRandom prg;
        try {
            prg = SecureRandom.getInstance("SHA1PRNG");

        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("NativePRNG not available", ex);
        }
        prg.setSeed(hashvalue.toByteArray()); // use hashvalue as seed for a form of a pseudo-random number generator
                                              // PRNG.

        BigInteger e;
        do {
            e = new BigInteger(q.bitLength(), prg);
        } while (e.compareTo(BigInteger.ZERO) == 0 || e.compareTo(q) >= 0);
        System.out.println("DEBUG: Challenge e from PRG: " + e);

        // Step 4: Compute response z = r - e * secretkey mod order
        BigInteger z = r.subtract(e.multiply(secretK)).mod(q);
        System.out.println("DEBUG: Response z: " + z);

        return new NizkDlProof(e, z);

        // Challenge is slightly biased
        // Benardo idea:
        // Use the hash as a seed for prg. (P random generator.). Instanciate a random
        // generator. Set the seed to the hash. //NOTE: should be solved.
    }

    /**
     * Verifies a NIZK proof for the discrete logarithm relation in a finite field.
     *
     * @param ctx   the Pvss context
     * @param pub   the public key.
     * @param proof the NizkDlProof containing the challenge and response.
     * @return true if the proof is valid; false otherwise.
     */
    public static boolean verifyProof(DhPvssContext ctx, BigInteger pub, NizkDlProof proof) {
        BigInteger p = ctx.getOrder();
        BigInteger q = ctx.getSubgroupOrder();
        BigInteger g = ctx.getGenerator();

        // Recompute A' = g^z * pub^e mod p.
        BigInteger APrime = g.modPow(proof.getResponse(), p)
                .multiply(pub.modPow(proof.getChallenge(), p))
                .mod(p);
        System.out.println("DEBUG: Recomputed commitment A': " + APrime);

        // Recompute the challenge from (g, pub, A')
        BigInteger computedChallenge = Hash.hashElements(ctx, pub, APrime).mod(q);
        System.out.println("DEBUG: Hash value for verification (mod q): " + computedChallenge);
        // Use the hash as seed for a PRG to generate the challenge.
        SecureRandom prg;
        try {
            prg = SecureRandom.getInstance("SHA1PRNG");

        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("NativePRNG not available", ex);
        }
        prg.setSeed(computedChallenge.toByteArray());

        BigInteger computedE;
        do {
            computedE = new BigInteger(q.bitLength(), prg);
        } while (computedE.compareTo(BigInteger.ZERO) == 0 || computedE.compareTo(q) >= 0);
        System.out.println("DEBUG: Recomputed challenge e: " + computedE);

        return computedE.equals(proof.getChallenge());

    }
}
