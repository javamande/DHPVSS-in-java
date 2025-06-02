package org.example.napdkg.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.example.napdkg.dto.EphemeralKeyDTO;
import org.junit.Before;
import org.junit.Test;

public class InMemoryPbbClientTest {
    private InMemoryPbbClient client;

    @Before
    public void setUp() {
        client = new InMemoryPbbClient();
    }

    @Test
    public void testPublishAndFetchEphemeralKeys() throws Exception {
        // Create two distinct EphemeralKeyDTOs
        EphemeralKeyDTO e1 = new EphemeralKeyDTO("id1", 1, "I am a public key", "I am a proof");
        EphemeralKeyDTO e2 = new EphemeralKeyDTO("id2", 2, "I am another public key", "I am another proof");

        // Publish them under the same topic
        client.publish("ephemeralKeys", e1);
        client.publish("ephemeralKeys", e2);

        // Fetch them back
        List<EphemeralKeyDTO> out = client.fetch("ephemeralKeys", EphemeralKeyDTO.class);
        assertEquals(2, out.size());
        assertTrue(out.contains(e1));
        assertTrue(out.contains(e2));
    }
}