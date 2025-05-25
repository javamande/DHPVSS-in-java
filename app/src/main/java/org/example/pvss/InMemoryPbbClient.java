package org.example.pvss;

import java.util.ArrayList;
import java.util.List;

public class InMemoryPbbClient implements PbbClient {
    private final List<Object> store = new ArrayList<>();

    @Override
    public void publish(String topic, Object msg) {
        store.add(msg);
    }

    @Override
    public <T> List<T> fetch(String topic, Class<T> clazz) {
        // simply cast every stored entry of type T
        List<T> out = new ArrayList<>();
        for (Object o : store) {
            if (clazz.isInstance(o))
                out.add(clazz.cast(o));
        }
        return out;
    }

    /** Non‐interface helper to inspect the raw store. */
    public Object[] getStored() {
        return store.toArray();
    }

    @Override
    public void delete(String topic, String id) throws Exception {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'delete'");
    }

}
