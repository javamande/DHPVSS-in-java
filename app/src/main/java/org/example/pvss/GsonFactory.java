package org.example.pvss;

import java.lang.reflect.Type;
import java.util.Base64;

import org.bouncycastle.math.ec.ECPoint;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

public class GsonFactory {
    public static Gson createGson() {
        return new GsonBuilder()
                // whenever you see an ECPoint, write out its compressed bytes as Base64
                .registerTypeAdapter(ECPoint.class, new JsonSerializer<ECPoint>() {
                    @Override
                    public JsonElement serialize(ECPoint src, Type typeOfSrc, JsonSerializationContext context) {
                        byte[] compressed = src.getEncoded(true);
                        String b64 = Base64.getEncoder().encodeToString(compressed);
                        return new JsonPrimitive(b64);
                    }
                })
                // BigInteger works by default, but you can register one if you need control
                .create();
    }
}
