package org.example.napdkg.bench;

import java.util.List;

import org.example.napdkg.core.PartyContext;
import org.example.napdkg.core.ShareVerificationPublish;
import org.example.napdkg.core.VerificationPhase;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Setup;
public class ThresholdBenchmark {

    @Setup(Level.Invocation)
    public void prepareVerifiers(BenchmarkState state) throws Exception {
        // Ensure each party has done VerificationPhase.VerifySharesFor(...) for all
        // dealers
        // and has published its threshold output.

        int needed = state.t + state.fa;

        // 1) If necessary, run the sharing‐and‐verification so that we have enough
        // “valid” shares
        // (basically same as in VerificationBenchmark).
        // We skip that here, assuming VerificationBenchmark already ran.

        // 2) Now each party publishes its threshold output
        for (PartyContext P : state.parties) {
            VerificationPhase vp = new VerificationPhase(P);
            vp.publishThresholdOutput();
        }

        // 3) Make sure at least (t + fa) threshold outputs exist in
        // "ShareVerificationOutput"
        List<ShareVerificationPublish> all;
        do {
            Thread.sleep(100);
            all = state.pbb.fetch("ShareVerificationOutput", ShareVerificationPublish.class);
        } while (all.size() < needed);
    }

    @Benchmark
    public void publishAndReconstructThreshold(BenchmarkState state) throws Exception {
        int needed = state.t + state.fa;

        // 4) Each party collects Q2 = ‘needed’ threshold outputs and calls
        // finalReconstruction
        for (PartyContext P : state.parties) {
            VerificationPhase vp = new VerificationPhase(P);

            // A) Collect + prune threshold outputs
            List<ShareVerificationPublish> Q2 = vp.collectAndPruneThresholdOutputs();

            // B) Reconstruct group key (inside finalReconstruction):
            vp.finalReconstruction(vp.getQ1(), Q2);
        }
    }
}
