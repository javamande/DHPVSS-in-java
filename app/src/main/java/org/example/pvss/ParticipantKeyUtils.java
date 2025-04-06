// package org.example.pvss;

// import java.util.ArrayList;
// import java.util.List;

// import org.bouncycastle.math.ec.ECPoint;

// public class ParticipantKeyUtils {

// // Extracts just the public keys from a list of participant key pairs using a
// // for-loop.
// public static List<ECPoint> extractPublicKeys(List<ParticipantKeyPair>
// participants) {
// List<ECPoint> pubKeys = new ArrayList<>(participants.size());
// for (ParticipantKeyPair pkPair : participants) {
// pubKeys.add(pkPair.getKeyPair().getPublic());
// }
// return pubKeys;
// }

// // Extracts public key and proof as a tuple (ParticipantKeyData) for each
// // participant.
// public static List<ParticipantKeyData>
// extractKeyData(List<ParticipantKeyPair> participants) {
// List<ParticipantKeyData> keyDataList = new ArrayList<>(participants.size());
// for (ParticipantKeyPair pkPair : participants) {
// keyDataList.add(pkPair.asKeyData());
// }
// return keyDataList;
// // }
// // }
