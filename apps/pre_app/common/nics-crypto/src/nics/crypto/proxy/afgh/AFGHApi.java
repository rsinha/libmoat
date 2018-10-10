package nics.crypto.proxy.afgh;


import java.util.Arrays;
import java.util.Random;

import com.sun.xml.internal.rngom.parse.host.Base;
import it.unisa.dia.gas.jpbc.*;
import org.apache.commons.codec.binary.Hex;
import com.google.gson.*;
import org.json.*;
import org.apache.commons.codec.binary.Base64;

public class AFGHApi {

    public static AFGHGlobalParameters generate_params() throws Exception {
        // 80 bits seg: r = 160, q = 512
        // 128 bits seg: r = 256, q = 1536
        // 256 bits seg: r = 512, q = 7680

        int rBits = 256; //160;    // 20 bytes
        int qBits = 1536; //512;    // 64 bytes

        AFGHGlobalParameters global = new AFGHGlobalParameters(rBits, qBits);
        return global;
    }

    public static JsonObject generate_pubpriv_key(AFGHGlobalParameters global, String name) throws Exception {
        Element sk = AFGHProxyReEncryption.generateSecretKey(global);
        byte[] pk = AFGHProxyReEncryption.generatePublicKey(sk.toBytes(), global);
        //System.out.printf("Within generate_pubpriv_key[%s]:\n", name);
        //print_byte_array("pk", pk);
        //print_element("sk", sk);

        String encoded_sk = new String(Base64.encodeBase64(sk.toBytes()));
        String encoded_pk = new String(Base64.encodeBase64(pk));

        JsonObject o = new JsonObject();
        o.addProperty("pk", encoded_pk);
        o.addProperty("sk", encoded_sk);
        return o;
    }

    public static JsonObject generate_delegate_key(AFGHGlobalParameters global, JsonObject i) throws Exception {
        //System.out.println("Within generate_delegate_key:");

        byte[] pk = Base64.decodeBase64(i.get("partner_pk").getAsString().getBytes());
        byte[] sk = Base64.decodeBase64(i.get("producer_sk").getAsString().getBytes());

        //print_byte_array("partner_pk", pk);
        //print_byte_array("producer_sk", sk);

        byte[] rk = AFGHProxyReEncryption.generateReEncryptionKey(pk, sk, global);
        //print_byte_array("rk", rk);

        String encoded_rk = new String(Base64.encodeBase64(rk));
        JsonObject o = new JsonObject();
        o.addProperty("rk", encoded_rk);
        return o;
    }

    public static JsonObject encrypt_msg(AFGHGlobalParameters global, JsonObject i) throws Exception {
        //System.out.println("Within encrypt_msg:");

        byte[] pk = Base64.decodeBase64(i.get("producer_pk").getAsString().getBytes());
        //print_byte_array("pk", pk);
        byte[] msg = i.get("plaintext").getAsString().getBytes();
        byte[] c = AFGHProxyReEncryption.secondLevelEncryption(msg, pk, global);
        //print_byte_array("c", c);

        JsonObject o = new JsonObject();
        o.addProperty("ciphertext", new String(Base64.encodeBase64(c)));
        return o;
    }

    public static JsonObject reencrypt_ctxt(AFGHGlobalParameters global, JsonObject i) throws Exception {
        //System.out.println("Within reencrypt_ctxt");
        byte[] rk = Base64.decodeBase64(i.get("rk").getAsString().getBytes());
        byte[] c = Base64.decodeBase64(i.get("ciphertext").getAsString().getBytes());
        //print_byte_array("c", c);
        //print_byte_array("rk", rk);

        byte[] c_new = AFGHProxyReEncryption.reEncryption(c, rk, global);
        //print_byte_array("c_new", c_new);

        JsonObject o = new JsonObject();
        o.addProperty("ciphertext", new String(Base64.encodeBase64(c_new)));
        return o;
    }

    public static JsonObject decrypt_ctxt(AFGHGlobalParameters global, JsonObject i) throws Exception {
        //System.out.println("Within decrypt_ctxt");
        byte[] sk = Base64.decodeBase64(i.get("sk").getAsString().getBytes());
        byte[] c = Base64.decodeBase64(i.get("ciphertext").getAsString().getBytes());

        byte[] m = AFGHProxyReEncryption.firstLevelDecryption(c, sk, global);
        //print_byte_array("msg", m);

        JsonObject o = new JsonObject();
        o.addProperty("plaintext", new String(m).trim());
        return o;
    }

    private static void test() throws Exception {
        byte[] kek = new byte[16];
        new Random().nextBytes(kek);
        String input = Base64.encodeBase64String(kek);
        System.out.printf("input[%d]: %s\n", input.length(), input);

        AFGHGlobalParameters params = generate_params();

        JsonObject producer_json = generate_pubpriv_key(params, "producer");
        JsonObject partner_json = generate_pubpriv_key(params, "partner");

        JsonObject request_json = new JsonObject();
        request_json.addProperty("producer_sk", producer_json.get("sk").getAsString());
        request_json.addProperty("partner_pk", partner_json.get("pk").getAsString());
        JsonObject delegate_json = generate_delegate_key(params, request_json);

        request_json = new JsonObject();
        request_json.addProperty("producer_pk", producer_json.get("pk").getAsString());
        request_json.addProperty("plaintext", input);
        JsonObject producer_ciphertext = encrypt_msg(params, request_json);

        request_json = new JsonObject();
        request_json.addProperty("rk", delegate_json.get("rk").getAsString());
        request_json.addProperty("ciphertext", producer_ciphertext.get("ciphertext").getAsString());
        JsonObject consumer_ciphertext = reencrypt_ctxt(params, request_json);

        request_json = new JsonObject();
        request_json.addProperty("sk", partner_json.get("sk").getAsString());
        request_json.addProperty("ciphertext", consumer_ciphertext.get("ciphertext").getAsString());
        JsonObject result = decrypt_ctxt(params, request_json);

        System.out.printf("Result: %s", result.get("plaintext").getAsString());
    }
}
