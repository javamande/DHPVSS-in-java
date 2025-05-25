package org.example.pvss;

import java.io.IOException;
import java.util.List;

/**
 * A very thin “bulletin‐board” client abstraction.
 * RoundOneService only ever calls these two methods.
 */
public interface PbbClient {
    void publish(String topic, Object msg)
            throws IOException, InterruptedException, Exception;

    default void publishAll(String topic, Object[] msgs)
            throws Exception {
        for (Object m : msgs)
            publish(topic, m);
    }

    <T> List<T> fetch(String topic, Class<T> clazz)
            throws IOException, InterruptedException, Exception;

    void delete(String topic, String id) throws Exception;

}
