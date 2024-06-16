package es.chiteroman.playintegrityfix;

import android.os.Build;
import android.util.Log;

import org.bouncycastle.asn1.x500.X500Name;
import org.json.JSONObject;

import java.lang.reflect.Field;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Objects;

public final class EntryPoint {
    private static final Map<Field, String> map = new HashMap<>();
    private static final Map<String, Keybox> certs = new HashMap<>();
    private static final Map<String, Certificate> store = new HashMap<>();

    static {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            Field keyStoreSpi = keyStore.getClass().getDeclaredField("keyStoreSpi");

            keyStoreSpi.setAccessible(true);

            CustomKeyStoreSpi.keyStoreSpi = (KeyStoreSpi) keyStoreSpi.get(keyStore);

        } catch (Throwable t) {
            LOG("Couldn't get keyStoreSpi: " + t);
        }

        Provider provider = Security.getProvider("AndroidKeyStore");

        Provider customProvider = new CustomProvider(provider);

        Security.removeProvider("AndroidKeyStore");
        Security.insertProviderAt(customProvider, 1);
    }

    public static void init(String json) {

        try {
            JSONObject jsonObject = new JSONObject(json);

            jsonObject.keys().forEachRemaining(s -> {
                try {
                    String value = jsonObject.getString(s);
                    Field field = getFieldByName(s);

                    if (field == null) {
                        LOG("Field " + s + " not found!");
                        return;
                    }

                    map.put(field, value);
                    LOG("Save " + field.getName() + " with value: " + value);

                } catch (Throwable t) {
                    LOG("Couldn't parse " + s + " key!");
                }
            });

            spoofFields();

        } catch (Throwable t) {
            LOG("Error loading json file: " + t);
        }
    }

    static void spoofFields() {
        map.forEach((field, s) -> {
            try {
                if (s.equals(field.get(null))) return;
                field.setAccessible(true);
                field.set(null, s);
                LOG("Set " + field.getName() + " field value: " + s);
            } catch (Throwable t) {
                LOG(t.toString());
            }
        });
    }

    public static void receiveXml(String data) {
        XMLParser xmlParser = new XMLParser(data);

        try {
            int numberOfKeyboxes = Integer.parseInt(Objects.requireNonNull(xmlParser.obtainPath(
                    "AndroidAttestation.NumberOfKeyboxes").get("text")));
            for (int i = 0; i < numberOfKeyboxes; i++) {
                String keyboxAlgorithm = xmlParser.obtainPath(
                        "AndroidAttestation.Keybox.Key[" + i + "]").get("algorithm");
                String privateKey = xmlParser.obtainPath(
                        "AndroidAttestation.Keybox.Key[" + i + "].PrivateKey").get("text");
                int numberOfCertificates = Integer.parseInt(Objects.requireNonNull(xmlParser.obtainPath(
                        "AndroidAttestation.Keybox.Key[" + i + "].CertificateChain.NumberOfCertificates").get("text")));

                LinkedList<Certificate> certificateChain = new LinkedList<>();
                LinkedList<X500Name> certificateChainHolders = new LinkedList<>();

                for (int j = 0; j < numberOfCertificates; j++) {
                    Map<String,String> certData= xmlParser.obtainPath(
                            "AndroidAttestation.Keybox.Key[" + i + "].CertificateChain.Certificate[" + j + "]");
                    certificateChain.add(CertUtils.parseCert(certData.get("text")));
                    certificateChainHolders.add(CertUtils.parseCertSubject(certData.get("text")));
                }
                certs.put(keyboxAlgorithm, new Keybox(CertUtils.parseKeyPair(privateKey),
                        CertUtils.parsePrivateKey(privateKey), certificateChain, certificateChainHolders));
            }
        } catch (Throwable t) {
            LOG("Error loading xml file: " + t);
        }
    }

    private static Field getFieldByName(String name) {

        Field field;
        try {
            field = Build.class.getDeclaredField(name);
        } catch (NoSuchFieldException e) {
            try {
                field = Build.VERSION.class.getDeclaredField(name);
            } catch (NoSuchFieldException ex) {
                return null;
            }
        }

        field.setAccessible(true);

        return field;
    }

    static void append(String a, Certificate c) {
        store.put(a, c);
    }

    static Certificate retrieve(String a) {
        return store.get(a);
    }

    static Keybox box(String type) {
        return certs.get(type);
    }

    static void LOG(String msg) {
        Log.d("PIF", msg);
    }
}
