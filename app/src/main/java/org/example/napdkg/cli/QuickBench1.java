package org.example.napdkg.cli;

import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.example.napdkg.client.GsonFactory;
import org.example.napdkg.client.HttpPbbClient;
import org.example.napdkg.client.InMemoryPbbClient;
import org.example.napdkg.client.InstrumentedPbbClient;
import org.example.napdkg.client.PbbClient;
import org.example.napdkg.core.DHPVSS_Setup;
import org.example.napdkg.core.PartyContext;
import org.example.napdkg.core.SetupPhasePublisher;
import org.example.napdkg.core.SetupPhaseWaiter;
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

public class QuickBench1 {
    private static final int NUM_ITERATIONS = 5;
    private static final int n = 160;
    private static final int t = n / 2 + 1;
    private static final int fa = 1;

    private static class TimingResult {
        double setupMs, sharingMs, verificationMs, thresholdMs, totalMs;
    }

    public static TimingResult runOnce(PbbClient raw) throws Exception {
        Logger log = LoggerFactory.getLogger(QuickBench1.class);
        Gson gson = GsonFactory.createGson();

        // 1) Global timer
        long startAll = System.nanoTime();

        // 2) Build PBB client (instrumented)
        PbbClient pbb = new InstrumentedPbbClient(raw, gson);

        // 3) DKG context
        GroupGenerator.GroupParameters gp = GroupGenerator.generateGroup();
        DkgContext ctx = DHPVSS_Setup.dhPvssSetup(gp, t, n);

        // 4) Executor with at most n threads (and no more than CPU cores)
        int threads = Math.min(Runtime.getRuntime().availableProcessors(), n);
        ExecutorService executor = Executors.newFixedThreadPool(threads);

        TimingResult result = new TimingResult();

        // —— Parallel clear old data ——
        List<Callable<Void>> clearTasks = new ArrayList<>();
        clearTasks.add(() -> {
            for (EphemeralKeyDTO e : pbb.fetch("ephemeralKeys", EphemeralKeyDTO.class))
                pbb.delete("ephemeralKeys", e.id);
            return null;
        });
        clearTasks.add(() -> {
            for (SharingOutputDTO sh : pbb.fetch("DealerPublish", SharingOutputDTO.class))
                pbb.delete("DealerPublish", sh.id);
            return null;
        });
        clearTasks.add(() -> {
            for (ShareVerificationOutputDTO so : pbb.fetch("ShareVerificationOutput", ShareVerificationOutputDTO.class))
                pbb.delete("ShareVerificationOutput", so.id);
            return null;
        });
        executor.invokeAll(clearTasks);

        // 5) Create PartyContexts
        List<PartyContext> parties = new ArrayList<>(n);
        for (int i = 0; i < n; i++)
            parties.add(new PartyContext(i, ctx, pbb, n, t, fa));

        // —— Phase 1: Setup ——
        long t0 = System.nanoTime();
        List<Callable<Void>> tasks = new ArrayList<>();
        for (PartyContext P : parties)
            tasks.add(() -> {
                SetupPhasePublisher.publishEphemeralKey(P);
                return null;
            });
        executor.invokeAll(tasks);
        for (PartyContext P : parties)
            SetupPhaseWaiter.awaitAllEphemeralKeys(P, n);
        result.setupMs = (System.nanoTime() - t0) / 1_000_000.0;

        // —— Phase 2: Sharing ——
        t0 = System.nanoTime();
        tasks.clear();
        for (PartyContext P : parties)
            tasks.add(() -> {
                new SharingPhase(P, t).runSharingAsDealer2();
                return null;
            });
        executor.invokeAll(tasks);
        result.sharingMs = (System.nanoTime() - t0) / 1_000_000.0;

        // —— Phase 3: Verification (stop at t+fa) ——
        t0 = System.nanoTime();
        tasks.clear();
        for (PartyContext P : parties)
            tasks.add(() -> {
                VerificationPhase vp = new VerificationPhase(P);
                int ok = 0;
                for (int d = 0; d < n && ok < (t + fa); d++) {
                    try {
                        vp.VerifySharesFor(d);
                        ok++;
                    } catch (Exception ignored) {
                    }
                }
                return null;
            });
        executor.invokeAll(tasks);
        result.verificationMs = (System.nanoTime() - t0) / 1_000_000.0;

        // —— Phase 4: Threshold + Reconstruction ——
        t0 = System.nanoTime();
        tasks.clear();
        for (PartyContext P : parties)
            tasks.add(() -> {
                VerificationPhase vp = new VerificationPhase(P);
                vp.publishThresholdOutput();
                return null;
            });
        executor.invokeAll(tasks);
        result.thresholdMs = (System.nanoTime() - t0) / 1_000_000.0;

        // 6) Total time
        long endAll = System.nanoTime();
        result.totalMs = (endAll - startAll) / 1_000_000.0;

        executor.shutdown();
        executor.awaitTermination(1, TimeUnit.MINUTES);
        return result;
    }

    public static void main(String[] args) throws Exception {
        // Flag “inmem” for in-memory PBB
        boolean inmem = args.length > 0 && args[0].equalsIgnoreCase("inmem");
        PbbClient raw = inmem
                ? new InMemoryPbbClient()
                : new HttpPbbClient("http://127.0.0.1:3003");

        List<TimingResult> results = new ArrayList<>(NUM_ITERATIONS);
        System.out.printf("Running %d iterations (%s mode)…%n%n",
                NUM_ITERATIONS, inmem ? "in-memory" : "HTTP");

        for (int i = 1; i <= NUM_ITERATIONS; i++) {
            System.out.printf("=== Iteration %d/%d ===%n", i, NUM_ITERATIONS);
            TimingResult tr = runOnce(raw);
            results.add(tr);
            System.out.printf(
                    "Setup: %8.3f ms | Sharing: %8.3f ms | Verification: %8.3f ms | Threshold: %8.3f ms | Total: %8.3f ms%n%n",
                    tr.setupMs, tr.sharingMs, tr.verificationMs, tr.thresholdMs, tr.totalMs);
        }

        // Aggregate statistics
        double[] sum = new double[5], sq = new double[5];
        for (TimingResult tr : results) {
            double[] v = { tr.setupMs, tr.sharingMs, tr.verificationMs, tr.thresholdMs, tr.totalMs };
            for (int j = 0; j < 5; j++) {
                sum[j] += v[j];
                sq[j] += v[j] * v[j];
            }
        }
        int N = results.size();
        String[] names = { "Setup", "Sharing", "Verification", "Threshold", "Total" };
        DecimalFormat df = new DecimalFormat("0.000");
        System.out.println("=== Summary (mean ± stddev) ===");
        for (int j = 0; j < 5; j++) {
            double mean = sum[j] / N;
            double var = (sq[j] - sum[j] * sum[j] / N) / (N - 1);
            System.out.printf("%-12s: %7s ms ± %7s ms%n",
                    names[j], df.format(mean), df.format(Math.sqrt(var)));
        }
    }
}
