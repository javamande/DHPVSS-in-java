// package org.example.napdkg.cli;

// import java.math.BigInteger;
// import java.util.ArrayList;
// import java.util.List;

// import org.bouncycastle.math.ec.ECPoint;
// import org.example.napdkg.client.GsonFactory;
// import org.example.napdkg.client.HttpPbbClient;
// import org.example.napdkg.client.InstrumentedPbbClient;
// import org.example.napdkg.client.PbbClient;
// import org.example.napdkg.core.DHPVSS_Setup;
// import org.example.napdkg.core.NapDkgParty;
// import org.example.napdkg.core.PartyContext;
// import org.example.napdkg.core.SetupPhasePublisher;
// import org.example.napdkg.core.SetupPhaseWaiter;
// import org.example.napdkg.core.ShareVerificationPublish;
// import org.example.napdkg.core.SharingOutput;
// import org.example.napdkg.core.SharingPhase;
// import org.example.napdkg.core.VerificationPhase;
// import org.example.napdkg.dto.EphemeralKeyDTO;
// import org.example.napdkg.dto.ShareVerificationOutputDTO;
// import org.example.napdkg.dto.SharingOutputDTO;
// import org.example.napdkg.util.DkgContext;
// import org.example.napdkg.util.GroupGenerator;
// import org.slf4j.Logger;
// import org.slf4j.LoggerFactory;

// import com.google.gson.Gson;

// public class SmokeTestNew {
// public static void main(String[] args) throws Exception {
// final Logger log = LoggerFactory.getLogger(NapDkgParty.class);
// int n = 6, t = 3, fa = 1;

// GroupGenerator.GroupParameters gp = GroupGenerator.generateGroup();
// DkgContext ctx = DHPVSS_Setup.dhPvssSetup(gp, t, n);
// Gson gson = GsonFactory.createGson();
// PbbClient raw = new HttpPbbClient("http://127.0.0.1:3010");
// PbbClient pbb = new InstrumentedPbbClient(raw, gson);

// System.out.println("heeloooooooooo" + ctx.getVs().toString());

// List<EphemeralKeyDTO> old = pbb.fetch("ephemeralKeys",
// EphemeralKeyDTO.class);
// for (EphemeralKeyDTO e : old) {
// // assuming you extend PbbClient with a delete(topic, id) method:
// pbb.delete("ephemeralKeys", e.id);

// }
// List<PartyContext> parties = new ArrayList<>(n);
// for (int i = 0; i < n; i++) {
// parties.add(new PartyContext(i, ctx, pbb, n, t, fa));
// }

// long start = System.nanoTime();
// // publish your own ephemeral key + proof
// for (PartyContext P : parties) {
// SetupPhasePublisher.publishEphemeralKey(P);
// }
// // block until each sees all n keys
// for (PartyContext P : parties) {
// SetupPhaseWaiter.awaitAllEphemeralKeys(P, n);
// }
// long setupNs = System.nanoTime() - start;

// // sanity check…
// if (pbb.fetch("ephemeralKeys", EphemeralKeyDTO.class).size() != n)
// throw new IllegalStateException("setup failed");
// System.out.println("✅ Setup smoke-test passed!");

// // 3) RUN SHARING PHASE
// // clean out any old shares

// List<EphemeralKeyDTO> oldpk = pbb.fetch("DealerPublish",
// EphemeralKeyDTO.class);
// for (EphemeralKeyDTO e : oldpk) {
// // assuming you extend PbbClient with a delete(topic, id) method:
// pbb.delete("DealerPublish", e.id);
// }
// List<SharingPhase> sharers = new ArrayList<>(n);
// start = System.nanoTime();
// for (PartyContext pc : parties) {
// SharingPhase sp = new SharingPhase(pc, t);
// // create the sharing‐phase instance and invoke it!
// sharers.add(sp);
// sp.runSharingAsDealer1();
// }
// // wait until at least t+fa of them show up
// List<SharingOutputDTO> shares;
// // 1) do the sharing‐round smoke‐test
// do {
// Thread.sleep(100);
// shares = pbb.fetch("DealerPublish", SharingOutputDTO.class);
// } while (shares.size() < t + fa);
// System.out.println("✅ Sharing round smoke-test passed!");

// BigInteger groupSecret = BigInteger.ZERO;
// for (SharingPhase sp : sharers) {
// groupSecret = groupSecret.add(sp.getSecretShare());
// }
// groupSecret = groupSecret.mod(ctx.getOrder());
// ECPoint Y_true = ctx.getGenerator().multiply(groupSecret);
// // now inject it into each verifier before they reconstruct:

// // 2) clear any old threshold‐outputs
// for (ShareVerificationOutputDTO dto : pbb.fetch("ShareVerificationOutput",
// ShareVerificationOutputDTO.class)) {
// pbb.delete("ShareVerificationOutput", dto.id);
// }

// // 1) Create exactly one VerificationPhase per PartyContext and hold them in
// a
// // list
// List<VerificationPhase> vps = new ArrayList<>();
// for (PartyContext p : parties) {
// vps.add(new VerificationPhase(p));
// }

// // 2) For each dealer 0..t+fa-1, have *every* vp verify that dealer’s shares.
// // This will populate vp.Q1 and vp.Aij / vp.aij.
// for (int dealer = 0; dealer < t + fa; dealer++) {
// for (VerificationPhase vp : vps) {
// vp.VerifySharesFor(dealer);
// }
// }
// // compute the true public key

// for (VerificationPhase vp : vps) {
// vp.setTrueGroupKey(Y_true);
// }
// log.info("=== Group Secret shares ===");
// for (SharingPhase sp : sharers) {
// log.info(" dealer {} → α_j = {}", sp.getMe(), sp.getSecretShare());
// }
// log.info("groupSecret = {}", groupSecret);
// log.info("Y_true = {}", Y_true);

// for (int i = 0; i < vps.size(); i++) {
// ECPoint recomputed = ctx.getGenerator().getCurve().getInfinity();
// for (SharingOutput sh : vps.get(i).getQ1()) {
// log.info(" Q1[{}] dealerPub = {}", sh.getDealerIndex(), sh.getDealerPub());
// recomputed = recomputed.add(sh.getDealerPub());
// }
// log.info("verifier {} sees sum-of-dealerPubs = {}", i, recomputed);
// }

// // 3) Now each vp publishes its own threshold‐output Θ_i
// for (VerificationPhase vp : vps) {
// vp.publishThresholdOutput();
// }

// // 4) And now each vp collects & prunes the first t+fa Θⱼ → its Q2, then
// // reconstructs
// for (VerificationPhase vp : vps) {
// List<ShareVerificationPublish> Q2 = vp.collectAndPruneThresholdOutputs();
// System.out.printf("✅ Q2 formed for party");
// vp.finalReconstruction(vp.getQ1(), Q2);
// }

// }
// }