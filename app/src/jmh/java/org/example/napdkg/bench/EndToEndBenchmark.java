package org.example.napdkg.bench;

import org.example.napdkg.cli.SmokeTestN3T1;
import org.openjdk.jmh.annotations.*;
import org.example.napdkg.core.PartyContext;
import org.example.napdkg.core.VerificationPhase;
import org.openjdk.jmh.annotations.Benchmark;

public class EndToEndBenchmark {

    @Benchmark
    public void runFullProtocol() throws Exception {
        // You will need to rename your SmokeTest (e.g. SmokeTestN3T1) to a static
        // method.
        // For example, if your class has:
        // public static void runOnce() throws Exception { …all of the steps… }
        // then do:
        SmokeTestN3T1.runOnce();
    }
}
