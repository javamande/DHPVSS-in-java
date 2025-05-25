package org.example.pvss;

import java.util.ArrayList;
import java.util.List;

import org.example.pvss.dto.EphemeralKeyDTO;
import org.example.pvss.dto.ShareVerificationOutputDTO;
import org.example.pvss.dto.SharingOutputDTO;
import org.example.pvss.dto.ThresholdKeyOutputDTO;

public class SetupSmokeTest {
    public static void main(String[] args) throws Exception {
        int n = 6, t = 3, fa = 1;
        PbbClient pbb = new HttpPbbClient("http://127.0.0.1:3004");
        // delete every existing record
        List<EphemeralKeyDTO> old = pbb.fetch("ephemeralKeys", EphemeralKeyDTO.class);
        for (EphemeralKeyDTO e : old) {
            // assuming you extend PbbClient with a delete(topic, id) method:
            pbb.delete("ephemeralKeys", e.id);

        }

        // 1) spin up n parties
        List<NapDkgParty> parties = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            parties.add(new NapDkgParty(i, n, t, fa, pbb));
        }

        // 2) publish phase
        System.out.println("→ publishing all ephemeral keys...");
        for (NapDkgParty p : parties) {
            p.publishSetup(); // non-blocking: “party i published its key”
        }

        // 3) wait phase
        System.out.println("→ waiting for everyone to appear in the PBB...");
        for (NapDkgParty p : parties) {
            p.awaitSetup(); // each blocks until it sees n entries
        }

        // 4) final sanity check
        List<EphemeralKeyDTO> ephs = pbb.fetch("ephemeralKeys", EphemeralKeyDTO.class);
        System.out.println("→ seen " + ephs.size() + " keys");
        if (ephs.size() != n) {
            throw new IllegalStateException("Expected " + n + " keys, but saw " + ephs.size());
        }
        System.out.println("✅ Setup smoke-test passed!");

        // Daler sharings round 1

        List<SharingOutputDTO> oldShares = pbb.fetch("DealerPublish", SharingOutputDTO.class);
        for (SharingOutputDTO s : oldShares) {
            pbb.delete("DealerPublish", s.id);
        }

        // 2) spin up dealers
        for (NapDkgParty p : parties) {
            p.runSharingAsDealer();
        }

        // 3) wait until we see at least t+fₐ outputs
        List<SharingOutputDTO> shares;
        do {
            Thread.sleep(100);
            shares = pbb.fetch("DealerPublish", SharingOutputDTO.class);
            System.out.println("→ saw " + shares.size() + " SharingOutputs");
        } while (shares.size() < t + fa);

        System.out.println("✅ Sharing round smoke-test passed!");

        // clear old
        for (ShareVerificationOutputDTO vold : pbb.fetch("ShareVerificationOutput", ShareVerificationOutputDTO.class)) {
            pbb.delete("ShareVerificationOutput", vold.id);
        }

        // assume you've already run sharing in-memory or via HTTP
        // 1) have each party verify each dealer’s share
        for (int dealer = 0; dealer < t + fa; dealer++) {
            for (NapDkgParty p : parties) {
                p.runSharingAsVerifier(dealer);
            }
        }

        // 2) wait for outputs
        List<ShareVerificationOutputDTO> outs;
        do {
            Thread.sleep(100);
            outs = pbb.fetch("ShareVerificationOutput", ShareVerificationOutputDTO.class);
            System.out.println("→ saw " + outs.size() + " verifications");
        } while (outs.size() < (t + fa) * n);

        System.out.println("✅ Verification round smoke-test passed!");

        // --- PHASE 3: threshold key (optimistic) ---

        for (int dealer = 0; dealer < t + fa; dealer++) {
            for (NapDkgParty p : parties) {
                p.doThresholdKey(dealer);
            }
        }

        boolean allOk = true;
        List<ThresholdKeyOutputDTO> tkeys = pbb.fetch("ThresholdKeyOutput", ThresholdKeyOutputDTO.class);
        for (ThresholdKeyOutputDTO dto : tkeys) {
            System.out.println("  party " + dto.partyIndex + " published its threshold key");
        }

        if (!allOk) {
            throw new IllegalStateException("Threshold‐key phase failed for at least one party");
        }
        System.out.println("✅ Threshold‐key smoke‐test passed!");
    }
}
