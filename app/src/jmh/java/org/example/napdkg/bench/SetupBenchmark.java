// file: src/jmh/java/org/example/napdkg/bench/SetupBenchmark.java
package org.example.napdkg.bench;

import org.example.napdkg.core.SetupPhasePublisher;
import org.example.napdkg.core.SetupPhaseWaiter;
import org.openjdk.jmh.annotations.Benchmark;

public class SetupBenchmark {

    @Benchmark
    public void publishAndAwaitAllKeys(BenchmarkState state) throws Exception {
        var parties = state.parties;
        int n = state.n;

        // (A) Publish ephemeral keys for all n parties
        for (var P : parties) {
            SetupPhasePublisher.publishEphemeralKey(P);
        }

        // (B) Wait until each party sees all n ephemeral keys
        for (var P : parties) {
            SetupPhaseWaiter.awaitAllEphemeralKeys(P, n);
        }
    }
}
