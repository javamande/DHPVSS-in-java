// file: src/jmh/java/org/example/napdkg/bench/BenchmarkState.java
package org.example.napdkg.bench;

import java.util.ArrayList;
import java.util.List;

import org.example.napdkg.client.HttpPbbClient;
import org.example.napdkg.client.InstrumentedPbbClient;
import org.example.napdkg.client.PbbClient;
import org.example.napdkg.core.DHPVSS_Setup;
import org.example.napdkg.core.PartyContext;
import org.example.napdkg.dto.EphemeralKeyDTO;
import org.example.napdkg.util.DkgContext;
import org.example.napdkg.util.GroupGenerator;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

@State(Scope.Benchmark)
public class BenchmarkState {
    public int n = 8;
    public int t = 3;
    public int fa = 1;

    public DkgContext ctx;
    public PbbClient pbb;
    public List<PartyContext> parties;

    @Setup(Level.Trial)
    public void setupTrial() throws Exception {
        // 1) Build DkgContext
        var gp = GroupGenerator.generateGroup();
        ctx = DHPVSS_Setup.dhPvssSetup(gp, t, n);

        // 2) Wrap a real HTTP PBB in an InstrumentedPbbClient (for bandwidth logging)
        pbb = new InstrumentedPbbClient(
                new HttpPbbClient("http://127.0.0.1:3010"),
                new com.google.gson.Gson());

        // 3) Clear any old ephemeral keys on the PBB
        for (EphemeralKeyDTO e : pbb.fetch("ephemeralKeys", EphemeralKeyDTO.class)) {
            pbb.delete("ephemeralKeys", e.id);
        }

        // 4) Instantiate n PartyContext instances
        parties = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            parties.add(new PartyContext(i, ctx, pbb, n, t, fa));
        }
    }
}
