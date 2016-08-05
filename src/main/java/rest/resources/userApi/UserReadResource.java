package rest.resources.userApi;

import com.orientechnologies.orient.core.record.impl.ODocument;
import org.apache.commons.codec.binary.Base64;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.restlet.Request;
import org.restlet.resource.Delete;
import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;
import trabe.AbePrivateKey;
import trabe.lw14.Lw14PrivateKeyComponent;
import rest.Storage;

import java.io.IOException;
import java.util.List;

public class UserReadResource extends ServerResource {

    @Get
    public synchronized JSONObject getUserBasePrivateKey() throws JSONException {
        Request req = getRequest();
        int uid = Integer.parseInt("" + req.getAttributes().get("userId"));

        JSONObject result = new JSONObject();

        final String success = "success";
        final String exists = "exists";
        final String privateKeyStr = "privatekey";
        final String secretSeedStr = "secretSeed";
        final String attributesStr = "attributes";

        Storage storage = Storage.getInstance();


        List<ODocument> users = storage.getByQuery("select * from User where uid = " + uid);
        if (users.size() == 0) {
            result.put(exists, false);
            result.put(success, true);
            return result;
        }

        ODocument user = users.get(0);
        byte[] privateKeyBytes = (byte[])user.field(privateKeyStr);
        AbePrivateKey privateKeyObj = null;
        try {
            privateKeyObj = AbePrivateKey.readFromByteArray(privateKeyBytes);
        } catch (IOException e) {
            result.put(success, false);
            return result;
        }
        JSONArray attributes = new JSONArray();
        List<Lw14PrivateKeyComponent> componentList = privateKeyObj.getComponents();
        if (componentList != null) {
            for (Lw14PrivateKeyComponent component : componentList) {
                attributes.put(component.attribute);
            }
        }

        if (user.containsField(privateKeyStr)) {
            result.put(exists, true);
            result.put(privateKeyStr, Base64.encodeBase64String(privateKeyBytes));
            result.put(secretSeedStr, Base64.encodeBase64String((byte[])user.field(secretSeedStr)));
            result.put(attributesStr, attributes);
        } else {
            result.put(exists, false);
        }
        result.put(success, true);

        return result;
    }

    @Delete
    public synchronized JSONObject deleteUserFromRecord() throws JSONException {
        Request req = getRequest();
        int uid = Integer.parseInt(""+req.getAttributes().get("userId"));

        JSONObject result = new JSONObject();

        final String success = "success";
        final String exist = "existed";

        Storage storage = Storage.getInstance();


        List<ODocument> users = storage.getByQuery("select * from User where uid = " + uid);
        if (users.size() == 0) {
            result.put(exist, false);
            result.put(success, true);
            return result;
        }

        ODocument user = users.get(0);
        user.delete();

        result.put(exist, true);
        result.put(success, true);

        return result;
    }
}
