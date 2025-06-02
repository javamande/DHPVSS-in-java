// package org.example.napdkg.cli;

// import java.util.ArrayList;
// import java.util.List;

// import org.example.napdkg.client.HttpPbbClient;
// import org.example.napdkg.client.PbbClient;
// import org.example.napdkg.core.NapDkgParty;

// import org.example.napdkg.dto.EphemeralKeyDTO;
// import org.example.napdkg.dto.ShareVerificationOutputDTO;
// import org.example.napdkg.dto.SharingOutputDTO;
// import org.example.napdkg.dto.ThresholdKeyOutputDTO;

// import org.slf4j.Logger;
// import org.slf4j.LoggerFactory;

// public class SetupSmokeTest {
// public static void main(String[] args) throws Exception {
// final Logger log = LoggerFactory.getLogger(NapDkgParty.class);
// int n = 6, t = 3, fa = 1;

// PbbClient pbb = new HttpPbbClient("http://127.0.0.1:3003");
// // delete every existing record
// List<EphemeralKeyDTO> old = pbb.fetch("ephemeralKeys",
// EphemeralKeyDTO.class);
// for (EphemeralKeyDTO e : old) {
// // assuming you extend PbbClient with a delete(topic, id) method:
// pbb.delete("ephemeralKeys", e.id);

// }

// // 1) spin up n parties
// List<NapDkgParty> parties = new ArrayList<>();
// for (int i = 0; i < n; i++) {
// parties.add(new NapDkgParty(i, n, t, fa, pbb));
// }

// // 2) publish phase
// log.info("→ publishing all ephemeral keys...");
// for (NapDkgParty p : parties) {
// p.runSetup(); // non-blocking: “party i published its key”
// }

// // 3) wait phase
// log.info("→ waiting for everyone to appear in the PBB...");
// for (NapDkgParty p : parties) {
// p.completeSetup(); // each blocks until it sees n entries
// }

// // 4) final sanity check
// List<EphemeralKeyDTO> ephs = pbb.fetch("ephemeralKeys",
// EphemeralKeyDTO.class);
// log.info("→ seen " + ephs.size() + " keys");
// if (ephs.size() != n) {
// throw new IllegalStateException("Expected " + n + " keys, but saw " +
// ephs.size());
// }
// log.info("✅ Setup smoke-test passed!");

// // Daler sharings round 1

// List<SharingOutputDTO> oldShares = pbb.fetch("DealerPublish",
// SharingOutputDTO.class);
// for (SharingOutputDTO s : oldShares) {
// pbb.delete("DealerPublish", s.id);
// }

// // 2) spin up dealers
// for (NapDkgParty p : parties) {
// p.runSharingAsDealer();
// }

// // 3) wait until we see at least t+fₐ outputs
// List<SharingOutputDTO> shares;
// do {
// Thread.sleep(100);
// shares = pbb.fetch("DealerPublish", SharingOutputDTO.class);
// log.info("→ saw " + shares.size() + " SharingOutputs");
// } while (shares.size() < t + fa);

// log.info("✅ Sharing round smoke-test passed!");

// // clear old
// for (ShareVerificationOutputDTO vold : pbb.fetch("ShareVerificationOutput",
// ShareVerificationOutputDTO.class)) {
// pbb.delete("ShareVerificationOutput", vold.id);
// }

// // assume you've already run sharing in-memory or via HTTP
// // 1) have each party verify each dealer’s share
// for (int dealer = 0; dealer < t + fa; dealer++) {
// for (NapDkgParty p : parties) {
// p.runSharingAsVerifier(dealer);
// }
// }

// // 2) wait for outputs
// List<ShareVerificationOutputDTO> outs;
// do {
// Thread.sleep(100);
// outs = pbb.fetch("ShareVerificationOutput",
// ShareVerificationOutputDTO.class);
// log.info("→ saw " + outs.size() + " verifications");
// } while (outs.size() < (t + fa) * n);

// log.info("✅ Verification round smoke-test passed!");

// // --- PHASE 3: threshold key (optimistic) ---

// }
// }