package integration.crypto;

import com.orientechnologies.orient.core.record.impl.ODocument;
import integration.FileOverwriteMitigation;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import integration.engine.JobQueue;
import trabe.AbePublicKey;
import trabe.AbeSecretMasterKey;
import rest.Storage;
import snet.entrance.*;

import java.io.*;
import java.util.*;

public class Encryptor extends Thread {
    private JSONObject manifest;
    private int containerId;

    private static final Logger logger = Logger.getLogger(Encryptor.class);

    /**
     * Create an encrypted container with the files in the manifest. Add ciphertext expiration jobs into the database and queue.
     * @param manifest    Encryption contract to create the container
     */
    public Encryptor(JSONObject manifest, int containerId) {
        this.manifest = manifest;
        this.containerId = containerId;
    }

    private boolean encrypt(){
        // TODO: add proper transaction management
        Storage storage = Storage.getInstance();
        JobQueue jobQueue = JobQueue.getInstance();
        final String containerIdStr = "cid";
        final String containerStatusStr = "status";
        final String containerFailStr = "failMsg";
        final String statusProcessingStr = "processing";
        final String statusSuccessStr = "success";
        final String statusFailStr = "failed";
        final String policyStr = "policy";
        final String pathStr = "path";
        final String expireStr = "expire";
        final String spanStr = "span";
        final String timezoneStr = "timezone";
        final String hidePolicyStr = "hidePolicy";
        final String expirTypeStr = "expirationType";
        final String expirDataStr = "expirationData";

        final ExpirationType EXPIRATION_TYPE = ExpirationType.TYPE2;

        storage.db.begin();

        ODocument container = new ODocument("Container");
        container.field(containerStatusStr, statusProcessingStr);
        container.field(containerIdStr, containerId);

        container.save();
        storage.db.commit();

        storage.db.begin();

        // retrieve local master key and public key
        AbeSecretMasterKey msk;
        try {
            msk = storage.getMSK();
        } catch (IOException e) {
            container.field(containerStatusStr, statusFailStr);
            container.field(containerFailStr, "Master key couldn't be read");

            container.save();
            storage.db.commit();
            return false;
        }

        boolean hidePolicy = false;
        try {
            hidePolicy = manifest.has(hidePolicyStr) && manifest.getBoolean(hidePolicyStr);
        } catch (JSONException e) {
            container.field(containerStatusStr, statusFailStr);
            container.field(containerFailStr, "Error reading the hidePolicy flag");

            container.save();
            storage.db.commit();
            return false;
        }

        AbePublicKey abePub = msk.getPublicKey();

        JSONArray files;
        String outfile;
        try {
            files = (JSONArray)manifest.get("files");
            outfile = (String)manifest.get("outfile");
        } catch (JSONException e) {
            container.field(containerStatusStr, statusFailStr);
            container.field(containerFailStr, "Couldn't find source files or output file properties in the manifest");

            container.save();
            storage.db.commit();
            return false;
        }

        ContainerBuilder cb = new ContainerBuilder();
        cb.setHidePolicy(hidePolicy);
        cb.setExpirationType(ExpirationType.NONE);

        if (manifest.has("owner")) {
            try {
                UserInfo ui = new UserInfo((org.json.simple.JSONObject)org.json.simple.JSONValue.parse(manifest.get("owner").toString()));
                cb.setUserInfo(ui);
            } catch (JSONException e) {
                container.field(containerStatusStr, statusFailStr);
                container.field(containerFailStr, "Couldn't find source files or output file properties in the manifest");

                container.save();
                storage.db.commit();
                return false;
            }
        }

        boolean overwriteFiles = true;
        try {
            if (manifest.has("overwriteOutfile")) {
                overwriteFiles = manifest.getBoolean("overwriteOutfile");
            }
        } catch (JSONException e) {
            logger.warn("Something went wrong with the overwrite flag", e);
        }


        LicenseEndpoint abeEndpoint = new LicenseEndpoint("vuze-general", AuthenticationType.NONE, EndpointType.DHT);
        //TODO: how to get the local address
        //LicenseEndpoint aesEndpoint = new LicenseEndpoint(local address, AuthenticationType.NONE, EndpointType.HTTP);

        int len = files.length();
        List<ODocument> fileBags = new ArrayList<ODocument>(len);

        for (int i = 0; i < len; i++) {
            JSONObject file = null;
            try {
                file = (JSONObject)files.get(i);
                if (file == null) {
                    throw new JSONException("File " + i + " was null");
                }
            } catch (JSONException e) {
                container.field(containerStatusStr, statusFailStr);
                container.field(containerFailStr, "File problem: " + e.getMessage());

                container.save();
                storage.db.commit();
                return false;
            }

            ODocument fileBag = new ODocument("FileBag");
            fileBags.add(fileBag);

            List<String> filenames = new ArrayList<String>(1);

            if (file.has("revoked")) {
                try {
                    JSONObject revoked = file.getJSONObject("revoked");
                    String type = revoked.getString("usersType");
                    JSONArray users = revoked.getJSONArray("users");
                    String[] usersStrings = new String[users.length()];
                    for (int j = 0; j < usersStrings.length; j++) {
                        usersStrings[j] = users.getString(j);
                    }

                    cb.setRevokedUsers(type, usersStrings);
                } catch (JSONException e) {
                    storage.db.rollback();

                    storage.db.begin();
                    container.field(containerStatusStr, statusFailStr);
                    container.field(containerFailStr, "Couldn't find source files or output file properties in the manifest");

                    container.save();
                    storage.db.commit();
                    return false;
                }
            }

            if (file.has(policyStr)) {
                List<ODocument> timeSpanDocs = new ArrayList<ODocument>();
                fileBag.field(expireStr, timeSpanDocs);

                // ABE
                try {
                    String policy = (String)file.get(policyStr);
                    String filePath = (String)file.get(pathStr);

                    filenames.add(filePath);
                    fileBag.field("filenames", filenames);
                    boolean expires = file.has(expireStr);

                    if (expires) {
                        JSONArray arr = (JSONArray)file.get(expireStr);
                        for(int j = 0; j < arr.length(); j++) {
                            JSONObject timeSpanJSON = arr.getJSONObject(j);
                            ODocument timeSpanDoc = new ODocument("Timespan");
                            JSONArray spanJson = timeSpanJSON.getJSONArray("span");

                            // it is assumed that the received timestamps have the same timezone as the server
                            timeSpanDoc.field("start", spanJson.getLong(0));

                            timeSpanDoc.field("releaseOnly", spanJson.length() == 1);
                            if (spanJson.length() != 1) {
                                timeSpanDoc.field("end", spanJson.getLong(1));
                            }

                            timeSpanDoc.save();
                            timeSpanDocs.add(timeSpanDoc);
                        }
                    }

                    logger.info("#enc: adding file with policy: '" + policy + "', in: '" + filePath + "', out: '" + outfile + "'");
                    logger.debug("#enc: final fileBag at location "+(fileBags.size()-1)+": " + fileBag.toJSON());

                    if (expires) {
                        cb.setExpirationType(EXPIRATION_TYPE);
                    }
                    cb.addFile(new File(filePath), policy, abePub, abeEndpoint);
                    cb.setExpirationType(ExpirationType.NONE);
                } catch (JSONException e) {
                    storage.db.rollback();

                    storage.db.begin();
                    container.field(containerStatusStr, statusFailStr);
                    container.field(containerFailStr, "File problem: " + e.getMessage());

                    container.save();
                    storage.db.commit();
                    return false;
                }
            } else {
                // AES
                storage.db.rollback();

                storage.db.begin();
                container.field(containerStatusStr, statusFailStr);
                container.field(containerFailStr, "Plain AES is not implemented");

                container.save();
                storage.db.commit();
                return false;
            }

            fileBag.save();
        }

        FileOutputStream out = null;
        Throwable exception = null;
        try {
            if (!overwriteFiles) {
                out = new FileOutputStream(FileOverwriteMitigation.findFreeFileName(new File(outfile)));
            } else {
                out = new FileOutputStream(outfile);
            }
            cb.buildIntoStream(out);
        } catch (IOException e) {
            exception = e;
        } catch (BuildException e) {
            exception = e;
        } finally {
            try {
                if (out != null) {
                    out.close();
                }
            } catch (IOException e) {
                exception = e;
            }
        }
        if (exception != null) {
            storage.db.rollback();

            storage.db.begin();

            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            exception.printStackTrace(pw);

            container.field(containerStatusStr, statusFailStr);
            container.field(containerFailStr, "Processing Exception: " + sw.toString());

            container.save();
            storage.db.commit();
            return false;
        } else {
            // save the generated external data in the
            List<byte[]> externalDataList = cb.getExternalData();
            for(int i = 0; i < externalDataList.size(); i++) {
                byte[] externalData = externalDataList.get(i);

                if (externalData == null) {
                    continue;
                }

                logger.debug("#enc: external data for " + i + "th fileBag: " + Hex.encodeHexString(externalData));

                ODocument fileBag = fileBags.get(i);
                fileBag.field(expirTypeStr, EXPIRATION_TYPE);
                fileBag.field(expirDataStr, externalData);
                fileBag.save();

                jobQueue.checkDocumentForQueue(fileBag);
            }

            container.field("fileBags", fileBags);
            container.field(containerStatusStr, statusSuccessStr);
        }

        container.save();
        storage.db.commit();

        return true;
    }

    public void run(){
        encrypt();
    }
}
