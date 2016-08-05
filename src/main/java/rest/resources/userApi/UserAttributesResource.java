package rest.resources.userApi;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.fge.jackson.JsonLoader;
import com.github.fge.jsonschema.main.JsonSchema;
import com.github.fge.jsonschema.main.JsonSchemaFactory;
import com.orientechnologies.orient.core.record.impl.ODocument;
import it.unisa.dia.gas.jpbc.Element;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.restlet.Request;
import org.restlet.representation.StringRepresentation;
import org.restlet.resource.Delete;
import org.restlet.resource.Get;
import org.restlet.resource.Put;
import org.restlet.resource.ServerResource;
import integration.engine.JobQueue;
import trabe.*;
import trabe.lw14.Lw14PrivateKeyComponent;
import trabe.policyparser.ParseException;
import rest.Storage;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;

public class UserAttributesResource extends ServerResource {
    
    private final char[] bannedAttributeChars = new char[]{ ' ', '\t', '\n', '\r', '<', '>', '(', ')' };
    private final char[] bannedNumericAttributeChars = new char[]{ '<', '>', '(', ')' };

    private static String MANIFEST = null;

    private static String getManifest() throws IOException {
        if (MANIFEST == null) {
            InputStream is = Thread.currentThread()
                    .getContextClassLoader()
                    .getResourceAsStream("userAttributeManifest.schema.json");
            MANIFEST = IOUtils.toString(is, "UTF-8");
        }

        return MANIFEST;
    }

    @Get("json")
    public JSONObject getAttributeForUser() throws JSONException {
        Request req = getRequest();
        final String exist = "existed";
        final String success = "success";
        final String msg = "msg";

        JSONObject result = new JSONObject();

        Storage storage = Storage.getInstance();

        int uid = Integer.parseInt(""+req.getAttributes().get("userId"));
        String attribute = ""+req.getAttributes().get("attributeName");

        System.out.println("uid " + uid + " att " + attribute);

        boolean numeric = attribute.indexOf('=') != -1;
        for (char c : (numeric ? bannedNumericAttributeChars : bannedAttributeChars)) {
            if (attribute.indexOf(c) != -1) {
                result.put(success, false);
                result.put(msg, "Illegal character in attribute: '" + c + "'");
                return result;
            }
        }

        ODocument user;

        List<ODocument> users = storage.getByQuery("select * from User where uid = " + uid);
        if (users.size() == 0) {
            result.put(exist, false);
            result.put(success, true);
            result.put(msg, "No such user");
            return result;
        }

        user = users.get(0);

        AbeSecretMasterKey msk = null;
        try {
            msk = storage.getMSK();
        } catch (IOException e) {
            e.printStackTrace();

            result.put(success, false);
            return result;
        }
        if (user.containsField("privatekey")) {
            byte[] pkBytes = (byte[])user.field("privatekey");
            AbePrivateKey oKey = null;
            try {
                oKey = AbePrivateKey.readFromByteArray(pkBytes);
            } catch (IOException e) {
                e.printStackTrace();

                result.put(exist, true);
                result.put(success, false);
                return result;
            }
            Lw14PrivateKeyComponent comp = oKey.getComponent(attribute);
            if (comp != null) {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                AbeOutputStream os = new AbeOutputStream(baos, msk.getPublicKey());
                try {
                    comp.writeToStream(os);
                    result.put("component", Base64.encodeBase64String(baos.toByteArray()));
                    result.put("name", attribute);
                    result.put("external", false);
                    result.put(exist, true);
                    result.put(success, true);
                    return result;
                } catch (IOException e) {
                    e.printStackTrace();
                    result.put(exist, true);
                    result.put(success, false);
                    return result;
                }
            }
        }

        result.put(exist, false);
        result.put(success, true);
        return result;
    }

    @Put("json")
    public synchronized JSONObject createAttributeForUser(StringRepresentation r) throws JSONException {
        Request req = getRequest();
        final String exist = "existed";
        final String success = "success";

        JSONObject result = new JSONObject();
        boolean external = false;

        if (r != null) {
            final String requestContent = r.getText();
            if (requestContent != null && requestContent.trim().length() > 0) {
                // input validation of the manifest
                try {
                    JsonNode manifestSchemaNode = JsonLoader.fromString(getManifest());
                    final JsonSchemaFactory factory = JsonSchemaFactory.byDefault();
                    JsonSchema manifestSchema = factory.getJsonSchema(manifestSchemaNode);
                    if (!manifestSchema.validInstance(JsonLoader.fromString(requestContent))) {
                        throw new Exception("Failed validation");
                    }
                } catch (Exception e) {
                    result.put(success, false);
                    e.printStackTrace();
                    return result;
                }

                JSONObject manifest = new JSONObject(requestContent);
                if (manifest.has("external")) {
                    external = manifest.getBoolean("external");
                }

                // TODO: read manifest.expire and use it
            }
        }

        Storage storage = Storage.getInstance();

        int uid = Integer.parseInt("" + req.getAttributes().get("userId"));
        String attributeName = ""+req.getAttributes().get("attributeName");

        int equalsIndex = attributeName.indexOf('=');
        if (equalsIndex != -1) {
            // only the name of the numerical attribute needs to be stored and not its value, because that might change
            attributeName = attributeName.substring(0, equalsIndex).trim();
        }

        System.out.println("uid " + uid + " att " + attributeName);

        ODocument user;

        storage.db.begin();

        List<ODocument> users = storage.getByQuery("select * from User where uid = " + uid);
        if (users.size() == 0) {
            result.put(exist, false);
            result.put(success, true);
            storage.db.rollback();
            return result;
        }

        user = users.get(0);

        try {
            AbeSecretMasterKey msk = storage.getMSK();
            AbeInputStream in = new AbeInputStream(new ByteArrayInputStream((byte[])user.field("secretElement")));
            in.setPublicKey(msk.getPublicKey());
            Element secretElement = in.readElement();
            in.close();

            AbePrivateKey key = Cpabe.keygen(msk,
                    attributeName,
                    new Pair<Element, Integer>(secretElement,
                            (Integer)user.field("userIndex")));

            // TODO: check that `key` contains at least one private key component

            if (external) {
                /*
                 * If the attribute is external, then its attribute secret element
                 * is not stored together with the static attribute secret elements
                 * in User#privatekey
                 * */
                ODocument attr = new ODocument("Attribute");
                attr.field("name", attributeName);
                attr.field("user", user);
                attr.field("data", key.getAsByteArray());
                attr.field("expirationType", "TYPE1");
                // TODO: maybe add indefinite Timespan or add definite timespan

                attr.save();

                Map<String, ODocument> extAttr;
                if (user.containsField("externalAttributes")) {
                    extAttr = user.field("externalAttributes");
                } else {
                    extAttr = new HashMap<String, ODocument>(1);
                    user.field("externalAttributes", extAttr);
                }
                extAttr.put(attributeName, attr);

                // call JobQueue with an update on an attribute
                JobQueue.getInstance().checkDocumentForQueue(attr); // maybe later
            } else {
                /*
                 * If the attribute is static, then it will be integrated into
                 * the private key of the user.
                 * */
                if (user.containsField("privatekey")) {
                    byte[] pkBytes = (byte[])user.field("privatekey");
                    AbePrivateKey oKey = null;
                    try {
                        oKey = AbePrivateKey.readFromByteArray(pkBytes);
                        key = oKey.merge(key);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }

                user.field("privatekey", key.getAsByteArray());
            }

            user.save();

            storage.db.commit();
        } catch(ParseException e) {
            result.put(success, false);
            e.printStackTrace();
            storage.db.rollback();
            return result;
        } catch (IOException e) {
            result.put(success, false);
            e.printStackTrace();
            storage.db.rollback();
            return result;
        }

        result.put(success, true);
        return result;
    }

    @Delete("json")
    public JSONObject revoke() throws JSONException {
        Request req = getRequest();
        final String userExists = "userExists";
        final String attributeExists = "attributeExists";
        final String success = "success";

        JSONObject result = new JSONObject();

        Storage storage = Storage.getInstance();

        int uid = Integer.parseInt("" + req.getAttributes().get("userId"));
        String attributeName = ""+req.getAttributes().get("attributeName");

        int equalsIndex = attributeName.indexOf('=');
        if (equalsIndex != -1) {
            // only the name of the numerical attribute needs to be stored and not its value, because that might change
            attributeName = attributeName.substring(0, equalsIndex).trim();
        }

        System.out.println("uid " + uid + " att " + attributeName);

        ODocument user;

        storage.db.begin();

        List<ODocument> users = storage.getByQuery("select * from User where uid = " + uid);
        if (users.size() == 0) {
            result.put(userExists, false);
            result.put(success, true);
            storage.db.rollback();
            return result;
        }

        user = users.get(0);
        result.put(userExists, true);

        boolean attrFound = false;

        // remove one static attribute
        if (user.containsField("privatekey")) {
            byte[] pkBytes = (byte[])user.field("privatekey");
            AbePrivateKey oKey = null;
            try {
                oKey = AbePrivateKey.readFromByteArray(pkBytes);
                Lw14PrivateKeyComponent found = null;
                for(Lw14PrivateKeyComponent comp : oKey.getComponents()) {
                    if (attributeName.equals(comp.attribute)) {
                        found = comp;
                        break;
                    }
                }
                if (found != null) {
                    oKey.getComponents().remove(found);
                    attrFound = true;

                    user.field("privatekey", oKey.getAsByteArray());

                    user.save();
                }
            } catch (IOException e) {
                result.put(success, false);
                e.printStackTrace();
                storage.db.rollback();
                return result;
            }
        }

        // revoke one dynamic/external attribute
        if (user.containsField("externalAttributes")) {
            Map<String, ODocument> externalAttributes = user.field("externalAttributes");

            if (externalAttributes.containsKey(attributeName)) {
                ODocument attr = externalAttributes.get(attributeName);

                attr.field("delete", true);
                attr.save();

                attrFound = true;

                JobQueue.getInstance().checkDocumentForQueue(attr);
            }
        }

        // fail if no attribute was revoked
        if (!attrFound) {
            result.put(attributeExists, false);
            result.put(success, false);
            storage.db.rollback();
            return result;
        }

        storage.db.commit();

        result.put(success, true);
        return result;
    }
}
