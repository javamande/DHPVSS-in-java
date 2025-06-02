package org.example.napdkg.bench;

import java.io.FileReader;
import java.text.DecimalFormat;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

/**
 * After running `./gradlew jmh`, point this LogAnalyzer at
 * “build/reports/jmh/benchmarks.json” to print a nice summary table.
 */
public class LogAnalyzer {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("Usage: LogAnalyzer <path/to/benchmarks.json>");
            System.exit(1);
        }

        String path = args[0];
        Gson gson = new Gson();
        List<Map<String, Object>> results = gson.fromJson(new FileReader(path),
                new TypeToken<List<Map<String, Object>>>() {
                }.getType());

        System.out.println("Benchmark         Mode  Ops/sec (mean ± stdDev)");
        System.out.println("------------------------------------------------");

        DecimalFormat df = new DecimalFormat("0.000");

        for (Map<String, Object> entry : results) {
            // Each entry in the array is a JSON object with keys like:
            // "benchmark" :
            // "org.example.napdkg.bench.SetupBenchmark.publishAndAwaitAllKeys",
            // "mode": "thrpt",
            // "primaryMetric" : { "score": xxx, "scoreError": yyy, ... }
            String benchFullName = (String) entry.get("benchmark");
            String[] parts = benchFullName.split("\\.");
            // We just want “SetupBenchmark.publishAndAwaitAllKeys”
            String shortName = parts[parts.length - 2] + "." + parts[parts.length - 1];

            String mode = (String) entry.get("mode");

            @SuppressWarnings("unchecked")
            Map<String, Object> primary = (Map<String, Object>) entry.get("primaryMetric");

            double score = ((Number) primary.get("score")).doubleValue();
            double scoreError = ((Number) primary.get("scoreError")).doubleValue();

            String line = String.format("%-35s %-5s %7s ± %5s",
                    shortName,
                    mode,
                    df.format(score),
                    df.format(scoreError));
            System.out.println(line);
        }
    }
}
