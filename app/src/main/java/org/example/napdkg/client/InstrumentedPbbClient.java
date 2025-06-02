package org.example.napdkg.client;

import java.nio.charset.StandardCharsets;
import java.util.List;

import com.google.gson.Gson;

/**
 * Wraps any PbbClient and counts bytes sent/received in JSON form.
 */
public class InstrumentedPbbClient implements PbbClient {
    private final PbbClient delegate;
    private final Gson gson;
    private long bytesSent = 0;
    private long bytesReceived = 0;

    public InstrumentedPbbClient(PbbClient delegate, Gson gson) {
        this.delegate = delegate;
        this.gson = gson;
    }

    @Override
    public void publish(String topic, Object msg) throws Exception {
        byte[] data = gson.toJson(msg).getBytes(StandardCharsets.UTF_8);
        bytesSent += data.length;
        delegate.publish(topic, msg);
    }

    @Override
    public void publishAll(String topic, Object[] msgs) throws Exception {
        for (Object m : msgs)
            publish(topic, m);
    }

    @Override
    public <T> List<T> fetch(String topic, Class<T> clazz) throws Exception {
        List<T> out = delegate.fetch(topic, clazz);
        String json = gson.toJson(out);
        bytesReceived += json.getBytes(StandardCharsets.UTF_8).length;
        return out;
    }

    @Override
    public void delete(String topic, String id) throws Exception {
        delegate.delete(topic, id);
    }

    /** How many bytes have we sent so far? */
    public long getBytesSent() {
        return bytesSent;
    }

    /** How many bytes have we received so far? */
    public long getBytesReceived() {
        return bytesReceived;
    }
}
