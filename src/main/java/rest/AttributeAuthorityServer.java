package rest;

import com.orientechnologies.orient.core.record.impl.ODocument;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.KeyPairGenerator;
import net.i2p.crypto.eddsa.spec.EdDSAGenParameterSpec;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.restlet.Application;
import org.restlet.Component;
import org.restlet.data.Protocol;
import org.restlet.engine.Engine;
import org.restlet.ext.json.JsonConverter;
import trabe.AbeSecretMasterKey;
import trabe.Cpabe;
import integration.engine.JobQueue;
import rest.resources.databaseViewApi.DatabaseViewResource;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;

public class AttributeAuthorityServer extends Application {

    public static void main(String[] args) throws Exception {
        Logger rootLogger = Logger.getRootLogger();
        Layout layout = new PatternLayout(PatternLayout.TTCC_CONVERSION_PATTERN);
        // rootLogger.addAppender(new ConsoleAppender(layout)); // There is already a console appender (Restlet)
        rootLogger.addAppender(new FileAppender(layout, "all.log"));
        Logger.getRootLogger().setLevel(Level.DEBUG);

        rootLogger.info("Starting at " + new Date());

        Security.addProvider(new BouncyCastleProvider());

        if (!ServerConfigDefaults.readConfig()) {
            System.out.println("Warning: Config file couldn't be read");
        }
        if (!ServerConfigDefaults.writeConfig()) {
            System.err.println("Couldn't write the config file");
        } else {
            System.out.println("Config file was written");
        }
        if (args.length > 0 && args[0].contains("init")) {
            return;
        }

        Runtime.getRuntime().addShutdownHook(new Thread() {
            public void run(){
                Storage.getInstance().close();
                if (!ServerConfigDefaults.writeConfig()) {
                    System.err.println("Couldn't write the config file");
                } else {
                    System.out.println("Config file was written on shutdown");
                }
            }
        });

        Storage storage = Storage.getInstance();
        AbeSecretMasterKey msk = storage.getMSK();
        if (msk == null) {
            msk = Cpabe.setup(ServerConfigDefaults.ABE_MAX_USERS);
            storage.setMSK(msk);
        }

        if (!storage.db.browseClass("EdDsaKeyPair").hasNext()) {
            /* key pair generation */
            KeyPairGenerator keyPairGenerator = new KeyPairGenerator();
            keyPairGenerator.initialize(
                    new EdDSAGenParameterSpec(ServerConfigDefaults.EDDSA_SPECIFICATION_STRING),
                    new SecureRandom()
            );
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            /* serializing keys */
            byte[] skBytes = ((EdDSAPrivateKey)keyPair.getPrivate()).getSeed();
            byte[] pkBytes = ((EdDSAPublicKey)keyPair.getPublic()).getAbyte();

            ODocument masterSigningKeyPair = new ODocument("EdDsaKeyPair");
            masterSigningKeyPair.field("type", ServerConfigDefaults.EDDSA_SPECIFICATION_STRING);
            masterSigningKeyPair.field("sk", skBytes);
            masterSigningKeyPair.field("pk", pkBytes);

            rootLogger.debug("PK: " + Hex.encodeHexString(pkBytes));
            rootLogger.debug("SK: " + Hex.encodeHexString(skBytes));

            storage.setDoc(masterSigningKeyPair);
        }

        // Create a new Component.
        Component component = new Component();

        // Add a new HTTP server listening on port 80 or some other configured port
        component.getServers().add(Protocol.HTTP, "127.0.0.1", ServerConfigDefaults.AA_API_PORT);

        component.getDefaultHost().attach("/encrypt", new EncryptionAPI());
        component.getDefaultHost().attach("/decrypt", new DecryptionAPI());
        component.getDefaultHost().attach("/user", new UserAPI());

        if (ServerConfigDefaults.DB_VIEW) {
            component.getDefaultHost().attach("/dbview", DatabaseViewResource.class);
        }

        Engine.getInstance().getRegisteredConverters().add(new JsonConverter());

        JobQueue.getInstance().init();

        // Start the component.
        component.start();
    }
}
