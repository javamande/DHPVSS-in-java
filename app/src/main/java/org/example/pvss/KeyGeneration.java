package org.example.pvss;

import java.security.NoSuchAlgorithmException;

/**
 * Key‐generation routines for DHPVSS (YOSO) protocols.
 */
public class KeyGeneration {

    /**
     * Generate a Diffie–Hellman key pair (sk, pk = G·sk) in the subgroup of order
     * p.
     *
     * @param ctx the DHPVSS context containing the curve generator G and subgroup
     *            order p
     * @return a DhKeyPair holding
     *         - secretKey ∈ Zₚ
     *         - publicKey = G·secretKey ∈ 𝔾
     */
    public static DhKeyPair generate(DhPvssContext ctx) {
        return DhKeyPair.generate(ctx);
    }

    /**
     * Generate a participant’s ephemeral key pair together with a Schnorr‐style
     * NIZK proof of discrete‐log knowledge.
     *
     * <p>
     * This binds the participant identifier id to the keypair. The proof asserts
     * ∃ x ∈ Zₚ such that
     * <ul>
     * <li>E = Gˣ (the ephemeral public key)</li>
     * <li>and x is known to the prover.</li>
     * </ul>
     *
     * @param ctx the DHPVSS context (for G and p)
     * @param id  the participant’s unique identifier (for audit/logging)
     * @return a ParticipantKeyPair containing
     *         - id
     *         - DhKeyPair(sk, pk=G·sk)
     *         - NizkDlProof of knowledge of sk
     * @throws NoSuchAlgorithmException if SHA-256 (for the Fiat–Shamir hash) is
     *                                  unavailable
     */
    public static ParticipantKeyPair generateForParticipant(DhPvssContext ctx, String id)
            throws NoSuchAlgorithmException {
        DhKeyPair basicKeyPair = generate(ctx);
        NizkDlProof proof = NizkDlProof.generateProof(ctx, basicKeyPair);
        return new ParticipantKeyPair(id, basicKeyPair, proof);
    }
}
