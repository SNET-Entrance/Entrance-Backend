package demo;

import static org.junit.Assert.*;

import edu.washington.cs.vanish.internal.backend.rpcimpl.RPCVanishBackendImpl;
import edu.washington.cs.vanish.logging.VanishLogger;
import integration.external.VuzeSubsystem;
import integration.external.ExternalKeyDistributionStorage;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.KeyPairGenerator;
import net.i2p.crypto.eddsa.spec.*;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import rest.ServerConfigDefaults;
import trabe.*;
import trabe.aes.AesEncryption;
import trabe.policyparser.ParseException;
import edu.washington.cs.vanish.conf.VanishConfiguration;
import edu.washington.cs.vanish.internal.VanishException;
import edu.washington.cs.vanish.internal.metadata.VDOParams;
import org.junit.Test;
import vanish.VanishHandler;

import java.io.IOException;
import java.security.*;
import java.util.Arrays;
import java.util.Random;

/**
 * This test requires a running Vanish server on localhost.
 */
public class VanishTest {
    @BeforeClass
    public static void setup(){
        Logger rootLogger = Logger.getRootLogger();
        rootLogger.setLevel(Level.DEBUG);
    }

    @Test
    public void testEncDecInHandler() throws VanishException{
        Random r = new Random();
        VanishHandler handler = new VanishHandler(new VanishConfiguration());
//        try {
//            handler.setVanishServiceURL(new URL("http://entrance2.snet.tu-berlin.de:10080/xmrpc"));
//        } catch (MalformedURLException e){
//            throw new VanishException("URL is malformed", e);
//        } catch (UnknownHostException e) {
//            throw new VanishException("Unknown host", e);
//        }
        byte[] msg = new byte[10];
        r.nextBytes(msg);
        byte[] vdo = handler.encapsulate(msg, new VDOParams());
        byte[] retrievedMsg = handler.decapsulate(vdo);
        assert(Arrays.equals(msg, retrievedMsg));
    }

    @Test
    public void testCpabeAndVanishInHandler() throws VanishException,
            AbeEncryptionException, DecryptionException, ParseException, IOException {
        SecureRandom r = new SecureRandom();
        VanishHandler handler = new VanishHandler(new VanishConfiguration());
//        try {
//            handler.setVanishServiceURL(new URL("http://entrance2.snet.tu-berlin.de:10080/xmrpc"));
//        } catch (MalformedURLException e){
//            throw new VanishException("URL is malformed", e);
//        } catch (UnknownHostException e) {
//            throw new VanishException("Unknown host", e);
//        }
        byte[] msg = new byte[1000];
        byte[] key1 = new byte[16];
        byte[] iv1 = new byte[16];
        r.nextBytes(msg);
        r.nextBytes(key1);
        r.nextBytes(iv1);

        byte[] ct1 = AesEncryption.encrypt(key1, null, iv1, msg);
        // TODO add iv1 to the beginning of ct1

        byte[] key2 = new byte[16];
        byte[] iv2 = new byte[16];
        r.nextBytes(key2);
        r.nextBytes(iv2);

        byte[] ct2 = AesEncryption.encrypt(key2, null, iv2, key1);
        // TODO add iv2 to the beginning of ct2

        byte[] vdo = handler.encapsulate(ct2, new VDOParams());

        byte[] finalCT = new byte[vdo.length+16];
        System.arraycopy(key2, 0, finalCT, 0, 16);
        System.arraycopy(vdo, 0, finalCT, 16, vdo.length);

        String attributes = "attr1";
        String policy = "attr1 or attr2";
        AbeSecretMasterKey mk = Cpabe.setup(2);
        AbePublicKey pk = mk.getPublicKey();
        AbeEncrypted abect = Cpabe.encrypt(pk, policy, finalCT);
        AbePrivateKey usk = Cpabe.keygenSingle(mk, attributes);

        // done with encryption
        // distribute abect and ct1
        // begin decryption

        byte[] decryptedCT = Cpabe.decrypt(usk, abect);

        byte[] dvdo = new byte[decryptedCT.length-16];
        byte[] dkey2 = new byte[16];
        System.arraycopy(decryptedCT, 0, dkey2, 0, 16);
        System.arraycopy(decryptedCT, 16, dvdo, 0, dvdo.length);

        assertTrue(Arrays.equals(vdo, dvdo));
        assertTrue(Arrays.equals(key2, dkey2));

        byte[] dct2 = handler.decapsulate(dvdo);
        assertTrue(Arrays.equals(ct2, dct2));

        byte[] dkey1 = AesEncryption.decrypt(dkey2, null, iv2, dct2);
        assertTrue(Arrays.equals(key1, dkey1));

        byte[] dmsg = AesEncryption.decrypt(dkey1, null, iv1, ct1);

        assertTrue(Arrays.equals(msg, dmsg));
    }

    @Test
    public void testDirectDhtAccess() throws Exception {
        int dataParts = 7;
        int dataLength = 512;

        VanishConfiguration config = new VanishConfiguration();
        //config.addProperty(RPCVanishBackendDefaults.CONF_VANISH_BACKEND_URL, "http://entrance2.snet.tu-berlin.de:10081/xmrpc");

        RPCVanishBackendImpl impl = new RPCVanishBackendImpl(config, VanishLogger.getLogger(VanishTest.class.toString()));
        impl.init();
        System.out.println("init done");

        Random r = new SecureRandom();

        byte[][] locs = new byte[dataParts][];
        byte[][] datas = new byte[dataParts][];

        for(int i = 0; i < dataParts; i++) {
            locs[i] = impl.generateLocation(r);
            datas[i] = new byte[dataLength];
            r.nextBytes(datas[i]);
        }
        System.out.println("loc gen done");


        long start = System.currentTimeMillis();
        impl.pushShares(datas, locs);
        long end = System.currentTimeMillis();

        System.out.println("push done in " + (end-start) + " ms");

        start = System.currentTimeMillis();
        byte[][] dhtDatas = impl.getShares(locs, dataParts);
        end = System.currentTimeMillis();

        System.out.println("get done in " + (end-start) + " ms");

        assertNotNull(dhtDatas);
        assertEquals(dhtDatas.length, dataParts);
        for(int i = 0; i < dataParts; i++) {
            assertTrue(Arrays.equals(datas[i], dhtDatas[i]));
        }
    }

    @Test
    public void testDhtSubsystemAccess() throws Exception {
        int dataParts = 3;
        int dataLength = 52;
        int locLength = 20;

        ExternalKeyDistributionStorage dht = VuzeSubsystem.getInstance();
        VanishConfiguration config = new VanishConfiguration();
        //config.addProperty(RPCVanishBackendDefaults.CONF_VANISH_BACKEND_URL, "http://entrance2.snet.tu-berlin.de:10081/xmrpc");

        RPCVanishBackendImpl impl = new RPCVanishBackendImpl(config, VanishLogger.getLogger(VanishTest.class.toString()));
        impl.init();
        System.out.println("init done");

        Random r = new SecureRandom();

        byte[][] locs = new byte[dataParts][];
        byte[][] datas = new byte[dataParts][];

        for(int i = 0; i < dataParts; i++) {
            locs[i] = new byte[locLength];
            r.nextBytes(locs[i]);
            datas[i] = new byte[dataLength];
            r.nextBytes(datas[i]);
        }
        System.out.println("loc gen done");


        long start = System.currentTimeMillis();
        dht.pushBulkData(locs, datas);
        long end = System.currentTimeMillis();

        System.out.println("push done in " + (end-start) + " ms");

        start = System.currentTimeMillis();
        byte[][] dhtDatas = dht.getBulkData(locs);
        end = System.currentTimeMillis();

        System.out.println("get done in " + (end-start) + " ms");

        assertNotNull(dhtDatas);
        assertEquals(dhtDatas.length, dataParts);
        for(int i = 0; i < dataParts; i++) {
            assertTrue(Arrays.equals(datas[i], dhtDatas[i]));
        }
    }

    @Test
    public void testEd25519() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidAlgorithmParameterException {
        SecureRandom r = new SecureRandom();

        /* message generation */
        byte[] msg = new byte[1234567];
        r.nextBytes(msg);

        /* key pair generation */
        KeyPairGenerator keyPairGenerator = new KeyPairGenerator();
        keyPairGenerator.initialize(new EdDSAGenParameterSpec(ServerConfigDefaults.EDDSA_SPECIFICATION_STRING), r);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        /* serializing keys */
        byte[] skBytes = ((EdDSAPrivateKey)keyPair.getPrivate()).getSeed();
        byte[] pkBytes = ((EdDSAPublicKey)keyPair.getPublic()).getAbyte();

        System.out.println("sk len: " + skBytes.length + ", pk len: " + pkBytes.length);

        /* deserializing keys */
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(ServerConfigDefaults.EDDSA_SPECIFICATION_STRING);

        EdDSAPublicKeySpec pkSpec = new EdDSAPublicKeySpec(pkBytes, spec);
        EdDSAPublicKey pk = new EdDSAPublicKey(pkSpec);

        EdDSAPrivateKeySpec skSpec = new EdDSAPrivateKeySpec(skBytes, spec);
        EdDSAPrivateKey sk = new EdDSAPrivateKey(skSpec);

        /* signing */
        Signature signatureSign = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
        signatureSign.initSign(sk);
        signatureSign.update(msg);
        byte[] signature = signatureSign.sign();

        /* verifying */
        Signature signatureVerify = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
        signatureVerify.initVerify(pk);
        signatureVerify.update(msg);
        assertTrue(signatureVerify.verify(signature));
    }
}
