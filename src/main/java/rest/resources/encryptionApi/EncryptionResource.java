package rest.resources.encryptionApi;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.fge.jackson.JsonLoader;
import com.github.fge.jsonschema.main.JsonSchema;
import com.github.fge.jsonschema.main.JsonSchemaFactory;
import com.orientechnologies.orient.core.db.document.ODatabaseDocumentTx;
import com.orientechnologies.orient.core.record.impl.ODocument;
import integration.crypto.Encryptor;
import org.apache.commons.io.IOUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.restlet.Request;
import org.restlet.representation.StringRepresentation;
import org.restlet.resource.Delete;
import org.restlet.resource.Get;
import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;
import integration.engine.JobQueue;
import trabe.*;
import rest.Storage;
import trabe.lw14.policy.Lw14PolicyAbstractNode;

import java.io.*;
import java.util.List;

public class EncryptionResource extends ServerResource {

    private static String REDUCED_MANIFEST = null;

    private static String getReducedManifest() throws IOException {
        if (REDUCED_MANIFEST == null) {
            InputStream is = Thread.currentThread()
                    .getContextClassLoader()
                    .getResourceAsStream("encryptionManifest.schema.json");
            REDUCED_MANIFEST = IOUtils.toString(is, "UTF-8");
        }

        return REDUCED_MANIFEST;
    }

    @Post
    public synchronized JSONObject encrypt(StringRepresentation r) throws JSONException, IOException {
        // FIXME: properly check concurrent requests
        final Request req = getRequest();
        final String successStr = "success";
        final String msgStr = "msg";
        final String requestContent = r.getText();

        int cid = Integer.parseInt(""+req.getAttributes().get("containerId"));

        JSONObject result = new JSONObject();

        // input validation of the partial manifest
        try {
            JsonNode manifestSchemaNode = JsonLoader.fromString(getReducedManifest());
            final JsonSchemaFactory factory = JsonSchemaFactory.byDefault();
            JsonSchema manifestSchema = factory.getJsonSchema(manifestSchemaNode);
            if (!manifestSchema.validInstance(JsonLoader.fromString(requestContent))) {
                throw new Exception("Failed validation");
            }
        } catch (Exception e) {
            result.put(successStr, false);
            result.put(msgStr, "Invalid reduced manifest");
            return result;
        }

        // System.out.println("Input: " + r.getText());
        JSONObject input = new JSONObject(requestContent);
        JSONArray files = (JSONArray)input.get("files");
        if (files == null || files.length() == 0) {
            result.put(successStr, false);
            result.put(msgStr, "No file names found in the manifest");
            return result;
        }

        Storage storage = Storage.getInstance();

        List availableContainers = storage.getByQuery("select * from Container where cid = " + cid);
        if (availableContainers.size() != 0) {
            result.put(successStr, false);
            result.put(msgStr, "Container with this ID already exists (try PUT request to change an existing container)");
            return result;
        }

        AbePublicKey pub = storage.getMSK().getPublicKey();
        Exception failed = null;
        JSONArray filesObj = input.getJSONArray("files");
        for (int i = 0; i < filesObj.length() && failed == null; i++) {
            JSONObject file = filesObj.getJSONObject(i);
            if (file.has("policy")) {
                try {
                    String postfixPolicy = trabe.policy.PolicyParsing.parsePolicy(file.getString("policy"));
                    Lw14PolicyAbstractNode.parsePolicy(postfixPolicy, pub);
                } catch (trabe.policyparser.ParseException e) {
                    failed = e;
                }
            }
        }

        if (failed != null) {
            result.put(successStr, false);
            result.put(msgStr, "There was a policy error: " + failed.getMessage());
            return result;
        }


        new Encryptor(input, cid).start();

        result.put(successStr, true);
        return result;
    }

    @Get
    public JSONObject getFileInfo() throws JSONException, IOException {
        final Request req = getRequest();
        final String successStr = "success";
        final String failedStr = "failed";
        final String failedMsgStr = "failMsg";
        final String msgStr = "msg";
        final String containerStatusStr = "status";

        int cid = Integer.parseInt(""+req.getAttributes().get("containerId"));

        JSONObject result = new JSONObject();

        Storage storage = Storage.getInstance();

        List<ODocument> availableContainers = storage.getByQuery("select * from Container where cid = " + cid);
        if (availableContainers.size() == 0) {
            result.put(successStr, false);
            result.put(msgStr, "Container with this ID not found");
            return result;
        }

        ODocument container = availableContainers.get(0);
        if (!container.containsField(containerStatusStr)) {
            result.put(successStr, false);
            result.put(msgStr, "Container with this ID doesn't have a status");
            return result;
        }

        String status = (String)container.field(containerStatusStr);
        result.put(containerStatusStr, status);
        System.out.println("### INFO status: " + status);
        if (failedStr.equals(status)) {
            result.put(failedMsgStr, container.getOriginalValue(failedMsgStr));
        }
        // TODO: maybe add other information such as the finish timestamp or something like that

        result.put(successStr, true);
        return result;
    }

    @Delete
    public JSONObject deleteContainer() throws JSONException, IOException {
        // straight up delete static containers from the database
        // don't delete dynamic containers, but schedule for expiration (JobQueue)

        final Request req = getRequest();
        final String successStr = "success";
        final String existedStr = "existed";
        final String expirationStr = "expirationInitiated";

        int cid = Integer.parseInt("" + req.getAttributes().get("containerId"));

        JSONObject result = new JSONObject();

        Storage storage = Storage.getInstance();

        ODatabaseDocumentTx tx = storage.db.begin();

        List<ODocument> availableContainers = storage.getByQuery("select * from Container where cid = " + cid);
        if (availableContainers.size() == 0) {
            result.put(successStr, true);
            result.put(existedStr, false);
            return result;
        }

        ODocument container = availableContainers.get(0);

        if (container.containsField("fileBags")) {
            List<ODocument> fileBags = container.field("fileBags");
            for(ODocument fb : fileBags) {
                if (fb.containsField("expirationType")) {
                    // FileBag needs immediate expiration
                    fb.field("delete", true);
                    storage.setDoc(fb);

                    JobQueue.getInstance().checkDocumentForQueue(container);

                    result.put(expirationStr, true);
                }
            }

            for(ODocument fb : fileBags) {
                if (fb.containsField("expire")) {
                    List<ODocument> timespans = fb.field("expire");
                    for(ODocument ts : timespans) {
                        ts.delete();
                    }
                }
            }
        }
        storage.db.commit();

        result.put(successStr, true);
        result.put(existedStr, true);

        return result;
    }
}
