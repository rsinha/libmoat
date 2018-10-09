/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package nics.crypto.proxy.afgh;

import java.util.Arrays;
import nics.crypto.Tuple;
import it.unisa.dia.gas.jpbc.*;
import org.apache.commons.codec.binary.Hex;
import com.google.gson.*;
import org.json.*;
import org.apache.commons.codec.binary.Base64;
/**
 *
 * @author david
 */
public class ProxyMain {
    /**
     * @param args the command line arguments
     */

    public static void print_element(String name, Element x) {
        System.out.printf("%s[%d]: ", name, x.toBytes().length);
        System.out.println(Hex.encodeHexString( x.toBytes() ));
    }

    public static AFGHGlobalParameters generate_params() throws Exception {
        // 80 bits seg: r = 160, q = 512
        // 128 bits seg: r = 256, q = 1536
        // 256 bits seg: r = 512, q = 7680

        int rBits = 256; //160;    // 20 bytes
        int qBits = 1536; //512;    // 64 bytes

        AFGHGlobalParameters global = new AFGHGlobalParameters(rBits, qBits);
        return global;
    }

    public static JsonObject generate_pubpriv_key(AFGHGlobalParameters global) throws Exception {
        Element sk = AFGHProxyReEncryption.generateSecretKey(global);
        Element pk = AFGHProxyReEncryption.generatePublicKey(sk, global);

        String encoded_sk = AFGHProxyReEncryption.elementToString(sk);
        String encoded_pk = AFGHProxyReEncryption.elementToString(pk);
        //String encoded_sk = new String(Base64.encodeBase64(sk.toBytes()));
        //String encoded_pk = new String(Base64.encodeBase64(pk.toBytes()));

        JsonObject o = new JsonObject();
        o.addProperty("pk", encoded_pk);
        o.addProperty("sk", encoded_sk);
        return o;
    }

    public static JsonObject generate_delegate_key(AFGHGlobalParameters global, JsonObject i) throws Exception {
        //String encoded_pk = new String(Base64.decodeBase64(i.get("partner_pk").getAsString()));
        //String encoded_sk = new String(Base64.decodeBase64(i.get("producer_sk").getAsString()));
        String encoded_pk = i.get("partner_pk").getAsString();
        String encoded_sk = i.get("producer_sk").getAsString();

        Element pk = AFGHProxyReEncryption.stringToElement(encoded_pk, global.getG2());
        Element sk = AFGHProxyReEncryption.stringToElement(encoded_sk, global.getG2());

        Element rk = AFGHProxyReEncryption.generateReEncryptionKey(pk, sk);

        String encoded_rk = AFGHProxyReEncryption.elementToString(rk);
        JsonObject o = new JsonObject();
        o.addProperty("rk", encoded_rk);
        return o;
    }


    public static void main(String[] args) throws Exception {
        AFGHGlobalParameters params = generate_params();
    }

    public static void test(String[] args) throws Exception {

        //java.security.

        //cpuTime = System.nanoTime();

        // 80 bits seg: r = 160, q = 512
        // 128 bits seg: r = 256, q = 1536
        // 256 bits seg: r = 512, q = 7680

        int rBits = 256; //160;    // 20 bytes
        int qBits = 1536; //512;    // 64 bytes

        AFGHGlobalParameters global = new AFGHGlobalParameters(rBits, qBits);



//        // Secret keys
//
//        byte[] sk_a = AFGH.generateSecretKey(global).toBytes();
//
//        System.out.println(medirTiempo());
//
//        byte[] sk_b = AFGH.generateSecretKey(global).toBytes();
//
//        System.out.println(medirTiempo());
//
//        // Public keys
//
//        byte[] pk_a = AFGH.generatePublicKey(sk_a, global);
//
//        System.out.println(medirTiempo());
//
//        byte[] pk_b = AFGH.generatePublicKey(sk_b, global);
//
//        System.out.println(medirTiempo());
//
//        // Re-Encryption Key
//
//        byte[] rk_a_b = AFGH.generateReEncryptionKey(pk_b, sk_a, global);
//
//        System.out.println(medirTiempo());
//
//        String message = "David";
//        byte[] m = message.getBytes();
//
//        System.out.println(medirTiempo());
//
//        byte[] c_a = AFGH.secondLevelEncryption(m, pk_a, global);
//
//        System.out.println(medirTiempo());
//
//        String c_a_base64 = Base64.encodeBase64URLSafeString(c_a);
//        //System.out.println("c_a_base64 = " + c_a_base64);
//
//        System.out.println(medirTiempo());
//
//        String rk_base64 = Base64.encodeBase64URLSafeString(rk_a_b);
//        //System.out.println("rk_base64 = " + rk_base64);
//        System.out.println(medirTiempo());
//
//        byte[] c, rk;
//        rk = Base64.decodeBase64(rk_base64);
//
//        System.out.println(medirTiempo());
//
//        c = Base64.decodeBase64(c_a_base64);
//
//        System.out.println(medirTiempo());
//
//        byte[] c_b = AFGH.reEncryption(c, rk, global);
//        //System.out.println("cb: " + Arrays.toString(c_b));
//        System.out.println(medirTiempo());
//
//        String c_b_base64 = Base64.encodeBase64URLSafeString(c_b);
//        //System.out.println("c_b_base64 = " + c_b_base64);
//
//        System.out.println(medirTiempo());
//
//        c = Base64.decodeBase64(c_b_base64);
//
//        System.out.println(medirTiempo());
//
//        byte[] m2 = AFGH.firstLevelDecryption(c_b, sk_b, global);
//        //System.out.println("m2:" + new String(m2));
//
//        System.out.println(medirTiempo());
//
//        assert message.equals(new String(m2).trim());
//
//        System.out.println();
//        System.out.println(global.toBytes().length);
//        System.out.println(sk_a.length);
//        System.out.println(sk_b.length);
//        System.out.println(pk_a.length);
//        System.out.println(pk_b.length);
//        System.out.println(rk_a_b.length);
//        System.out.println(m.length);
//        System.out.println(c_a.length);
//        System.out.println(c_b.length);
//
//        //
//        Map<String, byte[]> map = new HashMap<String, byte[]>();
//        map.put("sk_a", sk_a);
//        map.put("sk_b", sk_b);
//        map.put("pk_a", pk_a);
//        map.put("pk_b", pk_b);
//        map.put("rk_a_b", rk_a_b);
//        map.put("global", global.toBytes());
//        map.put("c_a_base64", c_a_base64.getBytes());
//
//        ObjectOutputStream fos = new ObjectOutputStream(new FileOutputStream("/Users/david/Desktop/pre.object"));
//        fos.writeObject(map);
//        fos.close();
        //

        // Secret keys

        Element sk_a = AFGHProxyReEncryption.generateSecretKey(global);
        print_element("sk_a", sk_a);

        //medirTiempoMicroSegundos();

        Element sk_b = AFGHProxyReEncryption.generateSecretKey(global);
        print_element("sk_b", sk_b);

        //medirTiempoMicroSegundos();

        Element sk_b_inverse = sk_b.invert();

        //medirTiempoMicroSegundos();

        // Public keys

        Element pk_a = AFGHProxyReEncryption.generatePublicKey(sk_a, global);
        print_element("pk_a", pk_a);

        //medirTiempoMicroSegundos();

        Element pk_b = AFGHProxyReEncryption.generatePublicKey(sk_b, global);
        print_element("pk_b", pk_b);

        //medirTiempoMicroSegundos();

        ElementPowPreProcessing pk_a_ppp = pk_a.pow();

        //medirTiempoMicroSegundos();

        // Re-Encryption Key

        Element rk_a_b = AFGHProxyReEncryption.generateReEncryptionKey(pk_b, sk_a);
        print_element("rk_a_b", rk_a_b);

        //medirTiempoMicroSegundos();

        String message = "12345678901234567890123456789012";
        Element m = AFGHProxyReEncryption.stringToElement(message, global.getG2());

        //medirTiempoMicroSegundos();

        Tuple c_a = AFGHProxyReEncryption.secondLevelEncryption(m, pk_a_ppp, global);

        //medirTiempoMicroSegundos();

        PairingPreProcessing e_ppp = global.getE().pairing(rk_a_b);

        //medirTiempoMicroSegundos();

        Tuple c_b = AFGHProxyReEncryption.reEncryption(c_a, rk_a_b, e_ppp);

        //medirTiempoMicroSegundos();

        Element m2 = AFGHProxyReEncryption.firstLevelDecryptionPreProcessing(c_b, sk_b_inverse, global);
        print_element("m2", m2);
        System.out.printf("message:%s\n", message);
        System.out.printf("m2: %s\n", Arrays.toString(m2.toBytes()));
        System.out.println(new String(m2.toBytes()).trim());

        //medirTiempoMicroSegundos();

        assert message.equals(new String(m2.toBytes()).trim());



//        System.out.println("m string : " + message.getBytes().length);
//        System.out.println("m in G2 : " + m.toBytes().length);
//        System.out.println("c_a_1 in G2: " + c_a.get(1).toBytes().length);
//        System.out.println("c_a_2 in G1: " + c_a.get(2).toBytes().length);
//        System.out.println("c_b_1 in G2: " + c_b.get(1).toBytes().length);
//        System.out.println("c_b_2 in G2: " + c_b.get(2).toBytes().length);
//        System.out.println("m2 in G2 : " + m2.toBytes().length);
        //System.out.println(AFGH.elementToString(m2));

        //System.out.println(medirTiempo());

    }

}
