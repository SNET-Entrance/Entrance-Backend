package rest.resources.encryptionApi;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.fge.jackson.JsonLoader;
import com.github.fge.jsonschema.main.JsonSchema;
import com.github.fge.jsonschema.main.JsonSchemaFactory;
import com.orientechnologies.orient.core.record.impl.ODocument;
import integration.crypto.Decryptor;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.util.encoders.Base64;
import org.json.JSONException;
import org.json.JSONObject;
import org.restlet.Request;
import org.restlet.representation.StringRepresentation;
import org.restlet.resource.Get;
import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;
import rest.Storage;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

public class DecryptionResource extends ServerResource {

    private static String DECRYPTION_MANIFEST = null;

    private static String getDecryptionManifest() throws IOException {
        if (DECRYPTION_MANIFEST == null) {
            InputStream is = Thread.currentThread()
                    .getContextClassLoader()
                    .getResourceAsStream("decryptionManifest.schema.json");
            DECRYPTION_MANIFEST = IOUtils.toString(is, "UTF-8");
        }

        return DECRYPTION_MANIFEST;
    }

    @Post
    public synchronized JSONObject decrypt(StringRepresentation r) throws JSONException, IOException {
        // FIXME: properly check concurrent requests
        final Request req = getRequest();
        final String successStr = "success";
        final String msgStr = "msg";
        final String requestContent = r.getText();

        int cid = Integer.parseInt(""+req.getAttributes().get("containerId"));

        JSONObject result = new JSONObject();

        // input validation of the partial manifest
        try {
            JsonNode manifestSchemaNode = JsonLoader.fromString(getDecryptionManifest());
            final JsonSchemaFactory factory = JsonSchemaFactory.byDefault();
            JsonSchema manifestSchema = factory.getJsonSchema(manifestSchemaNode);
            if (!manifestSchema.validInstance(JsonLoader.fromString(requestContent))) {
                throw new Exception("Failed validation");
            }
        } catch (Exception e) {
            result.put(successStr, false);
            result.put(msgStr, "Invalid decryption manifest");
            return result;
        }

        JSONObject input = new JSONObject(requestContent);

        Storage storage = Storage.getInstance();

        String privateKey = null;
        String secretSeed = null;
        boolean overwriteFiles = true;
        boolean checkExternal = false;

        try {
            JSONObject userData = input.getJSONObject("user");

            privateKey = userData.getString("privateKey");
            if (userData.has("secretSeed")) {
                secretSeed = userData.getString("secretSeed");
            }

            if (input.has("overwriteFilesInOutputDirectory")) {
                overwriteFiles = input.getBoolean("overwriteFilesInOutputDirectory");
            }

            if (input.has("checkExternal")) {
                checkExternal = input.getBoolean("checkExternal");
            }
        } catch (JSONException e) {
            Integer uid = input.getInt("user");

            List<ODocument> matchedUser = storage.getByQuery("select * from User where uid = " + uid);
            if (matchedUser.size() != 1) {
                result.put(successStr, false);
                result.put(msgStr, "User with this ID doesn't exist");
                return result;
            }

            byte[] privKey = matchedUser.get(0).field("privatekey");
            if (privKey == null || privKey.length == 0) {
                result.put(successStr, false);
                result.put(msgStr, "Private key for use doesn't exist");
                return result;
            }

            privateKey = Base64.toBase64String(privKey);

            byte[] secSeed = matchedUser.get(0).field("secretSeed");
            if (secSeed != null && secSeed.length > 0) {
                secretSeed = Base64.toBase64String(secSeed);
            }
        }

        boolean success = new Decryptor(input.getString("container"),
                input.getString("outputDirectory"), privateKey,
                secretSeed, overwriteFiles, checkExternal).decrypt();

        result.put(successStr, success);
        if (!success) {
            result.put(msgStr, "Something went wrong (Not enough attributes or something like that)");
        }
        return result;
    }

    @Get
    public JSONObject getFileInfo() throws JSONException, IOException {
        // copied from EncryptionResource
//        final Request req = getRequest();
        final String successStr = "success";
//        final String failedStr = "failed";
//        final String failedMsgStr = "failMsg";
//        final String msgStr = "msg";
//        final String containerStatusStr = "status";
//
//        int cid = Integer.parseInt(""+req.getAttributes().get("containerId"));

        JSONObject result = new JSONObject();

//        Storage storage = Storage.getInstance();
//
//        List<ODocument> availableContainers = storage.getByQuery("select * from Container where cid = " + cid);
//        if (availableContainers.size() == 0) {
//            result.put(successStr, false);
//            result.put(msgStr, "Container with this ID not found");
//            return result;
//        }
//
//        ODocument container = availableContainers.get(0);
//        if (!container.containsField(containerStatusStr)) {
//            result.put(successStr, false);
//            result.put(msgStr, "Container with this ID doesn't have a status");
//            return result;
//        }
//
//        String status = (String)container.field(containerStatusStr);
//        result.put(containerStatusStr, status);
//        System.out.println("### INFO status: " + status);
//        if (failedStr.equals(status)) {
//            result.put(failedMsgStr, container.getOriginalValue(failedMsgStr));
//        }

        result.put(successStr, false);
        result.put("implemented", false);
        result.put("todo", "The encryption is currently not asynchronous, because there are no decryption jobs in the database");
        return result;
    }
}
