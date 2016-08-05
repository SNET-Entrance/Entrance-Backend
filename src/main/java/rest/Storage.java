package rest;

import com.orientechnologies.orient.core.db.ODatabaseRecordThreadLocal;
import com.orientechnologies.orient.core.db.document.ODatabaseDocumentTx;
import com.orientechnologies.orient.core.iterator.ORecordIteratorClass;
import com.orientechnologies.orient.core.metadata.schema.OClass;
import com.orientechnologies.orient.core.metadata.schema.OType;
import com.orientechnologies.orient.core.record.impl.ODocument;
import com.orientechnologies.orient.core.sql.query.OSQLSynchQuery;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import org.apache.log4j.Logger;
import trabe.AbeSecretMasterKey;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.List;

public class Storage {
    private static Storage storage;

    private HashMap<String, Object> data = new HashMap<String, Object>();
    public final ODatabaseDocumentTx db;

    /*
    * Schema Changelog:
    *
    * Version 2:
    *   added expirationType to FileBag class as String
    *   added expirationData to FileBag class as Binary
    *
    * Version 3:
    *   added Attribute class
    *   added externalAttributes to User class as LinkSet of Attribute
    *   added parentFileBag and parentAttribute to Timespan class as a Link to either parent FileBag or parent Attribute
    *   added container to FileBag class as a Link to the parent Container
    *   added delete to FileBag and Attribute
    *   made secretSeed of User obligatory
    * */
    private static final int SCHEMA_VERSION = 3; // CHANGE THIS VERSION IF THE SCHEMA CHANGES AND ADD APPROPRIATE DATA MIGRATION CODE

    private static final Logger logger = Logger.getLogger(Storage.class);

    /**
     * Create the database and initialize the schema including changing the
     * schema and migrating the data to the new schema.
     */
    private Storage(){
        logger.info("Use memory DB: " + ServerConfigDefaults.DB_USE_MEMORY);
        logger.info("DB schema version: " + SCHEMA_VERSION);

        if (ServerConfigDefaults.DB_USE_MEMORY) {
            db = new ODatabaseDocumentTx("memory:attributeAuthority");
            if (!db.exists()) {
                db.create();
            }
        } else {
            ODatabaseDocumentTx tempdb = new ODatabaseDocumentTx("plocal:" + ServerConfigDefaults.DB_FOLDER_LOCATION);

            if (!tempdb.exists()) {
                logger.info("Create new DB in folder: " + ServerConfigDefaults.DB_FOLDER_LOCATION);
                tempdb = tempdb.create();
            } else {
                tempdb.open("admin", "admin");
            }

            db = tempdb;
        }

        ODocument baseDataShema;
        if (!db.getMetadata().getSchema().existsClass("DataSchema")) {
            logger.info("Create new DB class 'DataSchema'");

            OClass dataSchemaClass = db.getMetadata().getSchema().createClass("DataSchema");
            dataSchemaClass.createProperty("version", OType.INTEGER).setMandatory(true).setNotNull(true);
            baseDataShema = new ODocument("DataSchema");
            baseDataShema.field("version", SCHEMA_VERSION);
            baseDataShema.save();
        } else {
            baseDataShema = db.browseClass("DataSchema").next();
        }

        int schemaVersion = baseDataShema.field("version");

        boolean attributeClassExists = db.getMetadata().getSchema().existsClass("Attribute");
        boolean fileBagClassExists = db.getMetadata().getSchema().existsClass("FileBag");

        OClass attributeClass = db.getMetadata().getSchema().getOrCreateClass("Attribute");
        OClass fileBagClass = db.getMetadata().getSchema().getOrCreateClass("FileBag");

        OClass timespanClass;
        if (!db.getMetadata().getSchema().existsClass("Timespan")) {
            logger.info("Create new DB class 'Timespan'");

            timespanClass = db.getMetadata().getSchema().createClass("Timespan");
            timespanClass.createProperty("start", OType.DATETIME).setMandatory(true).setNotNull(true);
            timespanClass.createProperty("end", OType.DATETIME);
            timespanClass.createProperty("releaseOnly", OType.BOOLEAN);
            timespanClass.createProperty("strict", OType.BOOLEAN);
        } else {
            timespanClass = db.getMetadata().getSchema().getClass("Timespan");
        }

        boolean containerClassExists = db.getMetadata().getSchema().existsClass("Container");
        OClass containerClass = db.getMetadata().getSchema().getOrCreateClass("Container");

        if (!fileBagClassExists) {
            logger.info("Create new DB class 'FileBag'");

            fileBagClass.createProperty("filenames", OType.EMBEDDEDLIST, OType.STRING)
                    .setMandatory(true)
                    .setNotNull(true);
            fileBagClass.createProperty("expire", OType.LINKLIST, timespanClass);
            fileBagClass.createProperty("expirationType", OType.STRING);
            fileBagClass.createProperty("expirationData", OType.BINARY);
            fileBagClass.createProperty("container", OType.LINK, containerClass);
            fileBagClass.createProperty("delete", OType.BOOLEAN);
        } else {
            // migration code
            if (schemaVersion == 1) {
                fileBagClass.createProperty("expirationType", OType.STRING);
                fileBagClass.createProperty("expirationData", OType.BINARY);
            }

            if (schemaVersion < 3) {
                fileBagClass.createProperty("container", OType.LINK, containerClass);
                fileBagClass.createProperty("delete", OType.BOOLEAN);
            }
        }

        if (!containerClassExists) {
            logger.info("Create new DB class 'Container'");

            containerClass.createProperty("cid", OType.INTEGER).setMandatory(true).setNotNull(true);
            containerClass.createIndex("cidIdx", OClass.INDEX_TYPE.UNIQUE, "cid");

            containerClass.createProperty("status", OType.STRING).setMandatory(true).setNotNull(true);
            containerClass.createProperty("failMsg", OType.STRING);
            containerClass.createProperty("fileBags", OType.LINKLIST, fileBagClass);
        } else {
            // migration code
            if (schemaVersion < 3) {
                db.begin();
                for(ODocument cont : db.browseClass("Container")) {
                    if (!cont.containsField("fileBags")) continue;
                    for(ODocument fbl : ((List<ODocument>)cont.field("fileBags"))) {
                        fbl.field("container", cont);
                        fbl.save();
                    }
                }
                db.commit();
            }
        }

        boolean userClassExists = db.getMetadata().getSchema().existsClass("User");
        OClass userClass = db.getMetadata().getSchema().getOrCreateClass("User");

        // A document of the Attribute class should only be created when it is dynamic
        if (!attributeClassExists) {
            logger.info("Create new DB class 'Attribute'");

            attributeClass.createProperty("name", OType.STRING).setMandatory(true).setNotNull(true);
            attributeClass.createProperty("user", OType.LINK, userClass).setMandatory(true).setNotNull(true);
            attributeClass.createProperty("data", OType.BINARY).setMandatory(true).setNotNull(true);
            attributeClass.createProperty("delete", OType.BOOLEAN);
            attributeClass.createProperty("expire", OType.LINKLIST, timespanClass);
            attributeClass.createProperty("expirationType", OType.STRING);
            attributeClass.createProperty("expirationData", OType.BINARY);
        }

        if (!userClassExists) {
            logger.info("Create new DB class 'User'");

            userClass.createProperty("uid", OType.INTEGER).setMandatory(true).setNotNull(true);
            userClass.createIndex("uidIdx", OClass.INDEX_TYPE.UNIQUE, "uid");

            userClass.createProperty("id", OType.INTEGER).setMandatory(true).setNotNull(true);
            userClass.createProperty("userIndex", OType.INTEGER).setMandatory(true).setNotNull(true);
            userClass.createProperty("secretElement", OType.BINARY).setMandatory(true).setNotNull(true);
            userClass.createProperty("secretSeed", OType.BINARY).setMandatory(true).setNotNull(true);
            userClass.createProperty("privatekey", OType.BINARY);

            // new in version 3
            userClass.createProperty("externalAttributes", OType.LINKMAP, attributeClass);
        } else {
            if (schemaVersion < 3) {
                userClass.createProperty("externalAttributes", OType.LINKMAP, attributeClass);
                userClass.getProperty("secretSeed").setMandatory(true).setNotNull(true);
            }
        }

        if (!db.getMetadata().getSchema().existsClass("MSK")) {
            logger.info("Create new DB class 'MSK'");

            OClass mskClass = db.getMetadata().getSchema().getOrCreateClass("MSK");
            mskClass.createProperty("type", OType.STRING).setMandatory(true).setNotNull(true);
            mskClass.createProperty("value", OType.BINARY).setMandatory(true).setNotNull(true);
        }

        if (!db.getMetadata().getSchema().existsClass("EdDsaKeyPair")) {
            logger.info("Create new DB class 'EdDsaKeyPair'");

            OClass mskClass = db.getMetadata().getSchema().getOrCreateClass("EdDsaKeyPair");
            mskClass.createProperty("type", OType.STRING).setMandatory(true).setNotNull(true);
            mskClass.createProperty("sk", OType.BINARY).setMandatory(true).setNotNull(true);
            mskClass.createProperty("pk", OType.BINARY).setMandatory(true).setNotNull(true);
        }
    }

    /**
     * Creates a new storage object if none exists or returns the existing one.
     *
     * @return Storage
     */
    public static Storage getInstance() {
        if (storage == null) {
            storage = new Storage();
        }
        ODatabaseRecordThreadLocal.INSTANCE.set(storage.db);
        return storage;
    }

    /**
     * Sets a new Storage instance. This should be used for mocking the Storage singleton.
     * @param newStorage    New extending class instance
     * @return  the passed in instance
     */
    public static Storage setInstance(Storage newStorage) {
        storage = newStorage;
        return storage;
    }

    public void close() {
        if (db != null) {
            db.close();
        }
    }

    public boolean setMSK(AbeSecretMasterKey msk) throws IOException {
        // TODO: check if it already exists and if it does, return false and do nothing
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        msk.writeToStream(out);
        ODocument mskDoc = new ODocument("MSK");
        mskDoc.field("value", out.toByteArray());
        mskDoc.field("type", "PABE14");
        db.begin();
        mskDoc.save();
        db.commit();
        out.close();
        return true;
    }

    public AbeSecretMasterKey getMSK() throws IOException {
        AbeSecretMasterKey msk = null;
        db.begin();
        if (db.browseClass("MSK").hasNext()) {
            ODocument mskDoc = db.browseClass("MSK").next();
            msk = AbeSecretMasterKey.readFromByteArray((byte[])mskDoc.field("value"));
        }
        db.commit();

        return msk;
    }

    /**
     * Query the database for documents as a single transaction.
     * @param query    String query in the query language of OrientDB similar to SQL
     * @return  Retrieved documents
     */
    public List<ODocument> getByQuery(String query) {
        List<ODocument> documents;
        db.begin();
        documents = db.query(new OSQLSynchQuery<Object>(query));
        db.commit();

        return documents;
    }

    public PrivateKey getMasterSigningKey() {
        ORecordIteratorClass<ODocument> iter = db.browseClass("EdDsaKeyPair");
        if (!iter.hasNext()) {
            return null;
        }

        ODocument keyPair = iter.next();
        byte[] skBytes = keyPair.field("sk");

        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(ServerConfigDefaults.EDDSA_SPECIFICATION_STRING);
        EdDSAPrivateKeySpec skSpec = new EdDSAPrivateKeySpec(skBytes, spec);
        return new EdDSAPrivateKey(skSpec);
    }

    /**
     * Save the given document in a single transaction.
     * @param doc Database document to be persisted
     */
    public void setDoc(ODocument doc) {
        db.begin();
        doc.save();
        db.commit();
    }
}
