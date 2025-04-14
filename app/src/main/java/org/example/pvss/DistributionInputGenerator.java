package org.example.pvss;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;

public class DistributionInputGenerator {

    /**
     * Generates the inputs needed for the distribution phase.
     *
     * @param ctx    the PVSS context containing group parameters (including the EC
     *               group and generator).
     *               The context also embeds the number of participants.
     * @param random a source of secure randomness.
     * @return an instance of DistributionInput containing:
     *         - The dealer's key pair (skD, pkD).
     *         - A list of key pairs for the participants.
     *         - A secret S ∈ G.
     * @throws NoSuchAlgorithmException if the required PRNG algorithm is not
     *                                  available.
     */
    public static DistributionInput generateDistributionInput(DhPvssContext ctx, SecureRandom random)
            throws NoSuchAlgorithmException {
        int numParticipants = ctx.getNumParticipants();

        // Generate the dealer's key pair using your existing key pair generation
        // method.
        // (Note: DhKeyPair.generate uses the group parameters in the context.)
        DhKeyPair dealerKeyPair = DhKeyPair.generate(ctx, random);

        // Generate key pairs for each participant.
        // Here we keep the participant key pairs in a list.
        EphemeralKeyPublic[] ephemeralKeys = new EphemeralKeyPublic[numParticipants];
        for (int i = 0; i < numParticipants; i++) {
            // For each participant, generate an ephemeral key pair.
            // Here, we only require the public key. You might also generate a proof that
            // this key
            // is valid (using your existing DL proof generator, for example).
            DhKeyPair ephemeralKeyPair = DhKeyPair.generate(ctx, random);

            // Optionally, generate a DL proof for the ephemeral key.
            // For demonstration, we assume a proof is generated.
            NizkDlProof ephemeralProof = NizkDlProofGenerator.generateProof(ctx, ephemeralKeyPair);

            // Wrap in our container.
            ephemeralKeys[i] = new EphemeralKeyPublic(ephemeralKeyPair.getPublic(), ephemeralProof);
        }
        // Compute the secret S as S = [s]G.
        BigInteger s = new BigInteger(ctx.getGroupParameters().getN().bitLength(), random);
        ECPoint G = ctx.getGenerator();
        ECPoint secret = G.multiply(s).normalize();

        // Return the complete distribution input.
        return new DistributionInput(dealerKeyPair, ephemeralKeys, secret);
    }
}
