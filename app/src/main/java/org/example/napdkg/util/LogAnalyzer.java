package org.example.napdkg.util;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

/**
 * Parses a JSON array of numbers and prints count, mean, and standard
 * deviation.
 */
public class LogAnalyzer {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("Usage: LogAnalyzer <path-to-json-array>");
            System.exit(1);
        }
        String content = Files.readString(Path.of(args[0]));

        // Deserialize into a List<Double>
        List<Double> values = new Gson().fromJson(
                content,
                new TypeToken<List<Double>>() {
                }.getType());

        // Compute count and sum
        int count = values.size();
        double sum = 0.0;
        for (Double d : values) {
            sum += d;
        }
        double mean = sum / count;

        // Compute variance (sum of squared diffs)
        double sqDiffSum = 0.0;
        for (Double d : values) {
            double diff = d - mean;
            sqDiffSum += diff * diff;
        }
        double variance = sqDiffSum / count;
        double stddev = Math.sqrt(variance);

        System.out.printf("Count = %d, Mean = %.3f, Stddev = %.3f%n",
                count, mean, stddev);
    }
}
