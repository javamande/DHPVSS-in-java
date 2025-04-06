package org.example.pvss;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class DhKeyPairUtils {
    private static SecureRandom random = new SecureRandom();

    /**
     * Generates a basic finite-field keypair using the given group parameters.
     *
     * @param group the group parameters (p, g, subgroup order)
     * @return a DhKeyPair
     */
    public static DhKeyPair generate(DhPvssContext ctx) {
        return DhKeyPair.generate(ctx, random);
    }

    /**
     * Generates a keypair for a participant along with a DL proof.
     * The participant's identifier (id) is bound to the keypair.
     * Note: The actual implementation of DL proof generation is left as a
     * placeholder.
     *
     * @param group the group parameters
     * @param id    the participant's identifier
     * @return a ParticipantKeyPair containing the id, keypair, and proof
     * @throws NoSuchAlgorithmException
     */
    public static ParticipantKeyPair generateForParticipant(DhPvssContext ctx, String id)
            throws NoSuchAlgorithmException {
        DhKeyPair basicKeyPair = generate(ctx);
        // Generate the DL proof using a Schnorr-like protocol.
        // Replace the following line with your actual proof generation implementation.
        NizkDlProof proof = NizkDlProofGenerator.generateProof(ctx, basicKeyPair);
        return new ParticipantKeyPair(id, basicKeyPair, proof);
    }
}
