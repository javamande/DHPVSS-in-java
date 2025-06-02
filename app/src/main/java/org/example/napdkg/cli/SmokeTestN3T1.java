package org.example.napdkg.cli;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.math.ec.ECPoint;
import org.example.napdkg.client.GsonFactory;
import org.example.napdkg.client.HttpPbbClient;
import org.example.napdkg.client.InstrumentedPbbClient;
import org.example.napdkg.client.PbbClient;
import org.example.napdkg.core.DHPVSS_Setup;
import org.example.napdkg.core.PartyContext;
import org.example.napdkg.core.SetupPhasePublisher;
import org.example.napdkg.core.SetupPhaseWaiter;
import org.example.napdkg.core.ShareVerificationPublish;
import org.example.napdkg.core.SharingPhase;
import org.example.napdkg.core.VerificationPhase;
import org.example.napdkg.dto.EphemeralKeyDTO;
import org.example.napdkg.dto.ShareVerificationOutputDTO;
import org.example.napdkg.dto.SharingOutputDTO;
import org.example.napdkg.util.DkgContext;
import org.example.napdkg.util.GroupGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;

public class SmokeTestN3T1 {

    public static void runOnce() throws Exception {
        final Logger log = LoggerFactory.getLogger(SmokeTestN3T1.class);
        int n = 8, t = 3, fa = 1;

        // 1) Generate the group params (secp256r1 or whichever your code uses)
        GroupGenerator.GroupParameters gp = GroupGenerator.generateGroup();
        // 2) Build the DkgContext with n=3, t=1
        DkgContext ctx = DHPVSS_Setup.dhPvssSetup(gp, t, n);
        BigInteger[] α = ctx.getAlphas();
        BigInteger[] v = ctx.getVs();
        System.out.println(" α = " + Arrays.toString(α));
        System.out.println(" v = " + Arrays.toString(v));
        BigInteger order = ctx.getOrder();
        System.out.println("order is  " + order.toString(16));

        Gson gson = GsonFactory.createGson();
        // 3) Initialize the Public Bulletin Board
        // Adjust the URL if needed for your local PBB
        PbbClient raw = new HttpPbbClient("http://127.0.0.1:3010");
        PbbClient pbb = new InstrumentedPbbClient(raw, gson);

        log.info("Clearing old ephemeralKeys, old shares, old thresholds...");
        // Clear out old ephemeral keys, shares, threshold outputs, etc.
        for (EphemeralKeyDTO e : pbb.fetch("ephemeralKeys", EphemeralKeyDTO.class)) {
            pbb.delete("ephemeralKeys", e.id);
        }
        for (SharingOutputDTO sh : pbb.fetch("DealerPublish", SharingOutputDTO.class)) {
            pbb.delete("DealerPublish", sh.id);
        }
        for (ShareVerificationOutputDTO so : pbb.fetch("ShareVerificationOutput", ShareVerificationOutputDTO.class)) {
            pbb.delete("ShareVerificationOutput", so.id);
        }

        // 4) Create exactly n=3 PartyContext objects
        List<PartyContext> parties = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            parties.add(new PartyContext(i, ctx, pbb, n, t, fa));
        }
        BigInteger[] vs = ctx.getVs();
        System.out.println("Here are the vs from SMOKETESTN3T1 environment " + Arrays.toString(vs));
        // 5) Publish ephemeral keys
        log.info("Publishing ephemeral keys for each party...");
        for (PartyContext P : parties) {
            SetupPhasePublisher.publishEphemeralKey(P);
        }
        // Wait until each sees all n=3 ephemeral keys
        for (PartyContext P : parties) {
            SetupPhaseWaiter.awaitAllEphemeralKeys(P, n);
        }
        log.info("✅ Setup for n= " + n + "t= " + t + " complete!");

        // 6) Run sharing phase: each party is a dealer
        List<SharingPhase> sharers = new ArrayList<>(n);
        for (PartyContext pc : parties) {
            SharingPhase sp = new SharingPhase(pc, t);
            sharers.add(sp);
            sp.runSharingAsDealer2(); // post Sh_i to PBB
        }
        // Wait until at least t+fa=2 shares are published
        List<SharingOutputDTO> shares;
        do {
            Thread.sleep(200);
            shares = pbb.fetch("DealerPublish", SharingOutputDTO.class);
        } while (shares.size() < (t + fa)); // 2 in this scenario
        log.info("✅ At least {} dealers have published shares (we can verify).", shares.size());

        // 7) Sum the dealers' random secrets (for debugging).
        // We'll verify at the end that G^(sum) = final group key
        BigInteger groupSecretDebug = BigInteger.ZERO;
        for (SharingPhase sp : sharers) {
            // If you store your "real random secret r_i" in sp.getSecretShare(),
            // we sum them here. Some code uses sp.getSecretShare() for that.
            // Or if you have a different method name, adapt accordingly.
            BigInteger r = sp.getSecretShare();
            if (r == null) {
                System.err.println("❗ Null secret share for SharingPhase " + sp.getMe());
                continue; // or throw, or handle as you prefer
            }
            groupSecretDebug = groupSecretDebug.add(r).mod(ctx.getOrder());
        }
        ECPoint Y_debug = ctx.getGenerator().multiply(groupSecretDebug).normalize();

        // 8) Each party verifies the t+fa=2 or all 3 dealers
        List<VerificationPhase> vps = new ArrayList<>();
        for (PartyContext P : parties) {
            VerificationPhase vp = new VerificationPhase(P);
            vps.add(vp);

            // Verify each of the 3 dealers
            for (int dealerIndex = 0; dealerIndex < n; dealerIndex++) {
                vp.VerifySharesFor(dealerIndex);
            }
            // now the party presumably has a Q1 with all the validated dealers
        }

        // 9) Set the "trueGroupKey" = Y_debug in each verifier (for final check)
        for (VerificationPhase vp : vps) {
            vp.setTrueGroupKey(Y_debug);
        }

        log.info("=== Debug: groupSecret sum = {}", groupSecretDebug);
        log.info("Y_debug = {}", Y_debug);

        // 10) Now each party publishes threshold output
        for (VerificationPhase vp : vps) {
            vp.publishThresholdOutput();
        }

        // 11) Each party collects t+fa=2 threshold outputs -> Q2, then reconstruct
        for (VerificationPhase vp : vps) {
            List<ShareVerificationPublish> Q2 = vp.collectAndPruneThresholdOutputs();
            log.info("✅ Q2 formed for party {} with size {}", vp.getMe(), Q2.size());

            vp.finalReconstruction(vp.getQ1(), Q2);
        }
    }

    // Set up a small scenario: n=3, t=1, fa=1
    // so we have 3 parties, threshold 1 => any 2 can reconstruct
    // Slack fa=1 => we can handle 1 slow or missing dealer.

    public static void main(String[] args) throws Exception {
        runOnce();
    }
}