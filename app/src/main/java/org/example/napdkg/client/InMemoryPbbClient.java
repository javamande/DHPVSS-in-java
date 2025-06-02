package org.example.napdkg.client;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * InMemoryPbbClient keeps all “published” objects in memory, keyed by topic.
 *
 * Internally:
 * storage: Map<String topicName, Map<String id, Object dto>>
 *
 * fetch(...) on a missing topic now returns a mutable empty ArrayList<> (not
 * Collections.emptyList()).
 * publish(...) stores dto under its “id” (via reflection).
 * delete(...) on a missing (topic, id) now throws an IllegalArgumentException,
 * exactly what testDeleteThrows expects.
 */
public class InMemoryPbbClient implements PbbClient {

    // topicName → (id → dto)
    private final Map<String, Map<String, Object>> storage = new ConcurrentHashMap<>();

    @Override
    public <T> List<T> fetch(String topic, Class<T> clazz) {
        Map<String, Object> topicMap = storage.get(topic);
        if (topicMap == null) {
            // return a new, mutable empty list (not Collections.emptyList())
            return new ArrayList<>();
        }
        List<T> result = new ArrayList<>();
        for (Object o : topicMap.values()) {
            @SuppressWarnings("unchecked")
            T t = (T) o;
            result.add(t);
        }
        return result;
    }

    @Override
    public void publish(String topic, Object dto) {
        // ensure there is a map for this topic
        Map<String, Object> topicMap = storage.computeIfAbsent(topic,
                k -> new ConcurrentHashMap<>());

        // “id” extraction logic: try public field “id”, then getId(), else fallback to
        // toString()
        String id;
        try {
            java.lang.reflect.Field f = dto.getClass().getField("id");
            id = (String) f.get(dto);
        } catch (Exception e1) {
            try {
                java.lang.reflect.Method m = dto.getClass().getMethod("getId");
                id = (String) m.invoke(dto);
            } catch (Exception e2) {
                id = dto.toString();
            }
        }

        topicMap.put(id, dto);
    }

    @Override
    public void delete(String topic, String id) {
        Map<String, Object> topicMap = storage.get(topic);
        // If topic is missing or id is not present, throw IllegalArgumentException
        if (topicMap == null || !topicMap.containsKey(id)) {
            throw new IllegalArgumentException(
                    "No such ID '" + id + "' in topic '" + topic + "'");
        }
        // Otherwise remove
        topicMap.remove(id);
        if (topicMap.isEmpty()) {
            storage.remove(topic);
        }
    }
}
