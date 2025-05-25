package org.example.pvss;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class NapDkgDemo {
    public static void main(String[] args) throws Exception {
        // protocol parameters
        int n = 5; // total parties
        int t = 2; // threshold
        int fa = 1; // allowed faults

        // (1) one shared in‐memory PBB
        HttpPbbClient pbb = new HttpPbbClient("port:3000");

        // 1) instantiate parties P0…P(n−1)
        List<NapDkgParty> parties = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            parties.add(new NapDkgParty(i, n, t, fa, pbb));
        }

        System.out.println("\n** Setup (Round 1) **");
        // each party does Setup
        for (NapDkgParty p : parties) {
            p.runSetup();
        }
        // one party verifies all DL proofs
        NapDkgParty verifier = parties.get(0);
        List<EphemeralKeyPublic> pubs = verifier.getEphemeralPubs();
        for (int i = 0; i < n; i++) {
            EphemeralKeyPublic e = pubs.get(i);
            boolean ok = NizkDlProof.verifyProof(
                    parties.get(i).getContext(),
                    e.getPublicKey(),
                    e.getProof());
            if (!ok)
                throw new IllegalStateException("bad setup proof @ party " + i);
        }
        System.out.println("✅ Round 1 DL proofs verified!\n");

        System.out.println("** Sharing (Round 2 as dealers) **");
        // first (t+fa) parties act as dealers
        for (int dealer = 0; dealer < t + fa; dealer++) {
            parties.get(dealer).runSharingAsDealer();
            System.out.println("Dealer " + dealer + ": published encrypted shares");
        }
        System.out.println();

        // prepare thread pool
        ExecutorService exec = Executors.newFixedThreadPool(n);

        System.out.println("** Phase 2 (Share Verification) & Phase 3 (Optimistic TK) **");
        for (int dealer = 0; dealer < t + fa; dealer++) {
            // capture dealer into a final var
            final int D = dealer;

            // Phase 2: all parties verify shares for dealer D
            System.out.println("\n▶ Phase 2: Verifiers processing dealer " + D);
            List<Future<Integer>> vfs = new ArrayList<>();
            for (int i = 0; i < parties.size(); i++) {
                final NapDkgParty p = parties.get(i);
                final int idx = i;
                vfs.add(exec.submit(new Callable<Integer>() {
                    @Override
                    public Integer call() {
                        try {
                            p.runSharingAsVerifier(D);
                            return idx;
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    }
                }));
            }
            // print in order of party index
            for (Future<Integer> f : vfs) {
                int pi = f.get();
                System.out.println("Party " + pi + ": verified share for dealer " + D);
            }
            System.out.println("✅ All verifiers done for dealer " + D);

            // Phase 3: optimistic threshold‐key for dealer D

            // Phase 3: only the dealer publishes its Threshold-Key
            NapDkgParty dealerParty = parties.get(dealer);
            boolean ok = dealerParty.doThresholdKey(dealer);
            System.out.println("Dealer " + dealer + ": Threshold DLEQ ok? " + ok);

            System.out.println("✅ Threshold-Key done for dealer " + D);
        }
        exec.shutdown();
        System.out.println("\n🎉 All done!");
    }
}
