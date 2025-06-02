// src/main/java/org/example/napdkg/core/SetupPhasePublisher.java
package org.example.napdkg.core;

import org.example.napdkg.dto.EphemeralKeyDTO;
import org.example.napdkg.util.DkgUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SetupPhasePublisher {
    private static final Logger log = LoggerFactory.getLogger(SetupPhasePublisher.class);

    public static void publishEphemeralKey(PartyContext P) throws Exception {
        // generate & store this party’s ephemeral keypair
        DhKeyPair kp = DhKeyPair.generate(P.ctx);
        P.ephKey = kp;

        String id = "id" + P.id;
        String Phex = DkgUtils.encodePoint(kp.getPublic());
        NizkDlProof proof = NizkDlProof.generateProof(P.ctx, kp);
        String proofHex = proof.getChallenge().toString(16)
                + "|" + proof.getResponse().toString(16);

        EphemeralKeyDTO dto = new EphemeralKeyDTO(id, P.id, Phex, proofHex);

        try {
            P.pbb.publish("ephemeralKeys", dto);
            log.info("party {} published: {}", P.id, dto);
        } catch (Exception ex) {
            log.error("party {} publish failed", P.id, ex);
            throw ex;
        }
    }
}
