package rest.resources.userApi;

import com.orientechnologies.orient.core.iterator.ORecordIteratorClass;
import com.orientechnologies.orient.core.record.impl.ODocument;
import com.orientechnologies.orient.core.storage.ORecordDuplicatedException;
import it.unisa.dia.gas.jpbc.Element;
import org.apache.commons.codec.binary.Base64;
import org.json.JSONException;
import org.json.JSONObject;
import org.restlet.representation.StringRepresentation;
import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;
import trabe.AbeOutputStream;
import trabe.AbePrivateKey;
import trabe.AbeSecretMasterKey;
import trabe.Cpabe;
import trabe.Pair;
import trabe.policyparser.ParseException;
import rest.Storage;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

public class UserCreationResource extends ServerResource {

    /**
     * Create a new user with the passed uid and store the generated user secret key internally.
     * @return Success
     */
    @Post
    public synchronized JSONObject createNewUser(StringRepresentation r) throws JSONException {
        int uid = 0;

        JSONObject result = new JSONObject();

        final String success = "success";
        final String message = "msg";

        try {
            uid = Integer.parseInt(r.getText());
        } catch (NumberFormatException e) {
            result.put(success, false);
            return result;
        }

        Storage storage = Storage.getInstance();

        AbeSecretMasterKey msk = null;
        try {
            msk = storage.getMSK();
        } catch (IOException e) {
            e.printStackTrace();

            result.put(success, false);
            return result;
        }

        Pair<Element, Integer> priv = Cpabe.preKeygen(msk);

        SecureRandom random = new SecureRandom();
        byte[] secretSeed = new byte[128];
        random.nextBytes(secretSeed);

        int newId;
        try {
            newId = (int)storage.db.countClass("User");
        } catch (IllegalArgumentException e) {
            newId = 0;
        }

        ODocument user = new ODocument("User");
        user.field("id", newId);
        user.field("uid", uid);


        try {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            AbeOutputStream out = new AbeOutputStream(bout, msk.getPublicKey());
            out.writeElement(priv.getFirst());
            user.field("secretElement", bout.toByteArray());
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
            result.put(success, false);
            return result;
        }
        user.field("userIndex", priv.getSecond());
        user.field("secretSeed", secretSeed);

        ORecordIteratorClass<ODocument> kpIter = storage.db.browseClass("EdDsaKeyPair");
        if (!kpIter.hasNext()) {
            result.put(success, false);
            result.put(message, "master signing key not found");
            return result;
        }

        ODocument masterSigningKeyPair = kpIter.next();

        try {
            AbePrivateKey privateKey = Cpabe.keygen(msk, priv);
            if (privateKey == null) {
                result.put(success, false);
                return result;
            }

            privateKey.setAdditionalData("secretSeed", secretSeed);
            privateKey.setAdditionalData("authorityVerifyKey", (byte[])masterSigningKeyPair.field("pk"));
            byte[] privateKeyBytes = privateKey.getAsByteArray();
            user.field("privatekey", privateKeyBytes);
            result.put("privateKey", Base64.encodeBase64String(privateKeyBytes));
            result.put("secretSeed", Base64.encodeBase64String(secretSeed)); // TODO: obsolete and can be deleted

            result.put(success, true);
            storage.setDoc(user);
        } catch (ParseException e) {
            e.printStackTrace();
            result.put(success, false);
        } catch (IOException e) {
            e.printStackTrace();
            result.put(success, false);
        } catch (ORecordDuplicatedException e) {
            e.printStackTrace();
            result.put(success, false);
        }


        return result;
    }
}
