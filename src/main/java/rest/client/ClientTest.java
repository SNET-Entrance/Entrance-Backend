package rest.client;

import org.apache.commons.codec.binary.Base64;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.restlet.representation.Representation;
import org.restlet.resource.ClientResource;
import trabe.AbePrivateKey;
import rest.ServerConfigDefaults;
import snet.entrance.ContainerReader;
import snet.entrance.ParseException;

import java.io.*;
import java.util.Arrays;
import java.util.Date;

public class ClientTest {

    public static byte[] getByteResponse(String uri) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new ClientResource(uri).get().write(baos);
        return baos.toByteArray();
    }

    public static String getStringResponse(String uri) throws IOException {
        return new String(getByteResponse(uri), "UTF-8");
    }

    public static JSONArray getJsonArrayResponse(String uri) throws IOException, JSONException {
        return new ClientResource(uri).get(JSONArray.class);
    }

    public static JSONObject getJsonObjectResponse(String uri) throws IOException, JSONException {
        return new ClientResource(uri).get(JSONObject.class);
    }

    public static JSONObject postStringAndGetJsonObjectResponse(String uri, String data) throws IOException, JSONException {
        return new ClientResource(uri).post(data, JSONObject.class);
    }

    public static void main(String[] args) throws IOException, JSONException, ParseException, InterruptedException {
        Representation r;
        JSONObject o;
        ServerConfigDefaults.readConfig();
        final String l = "http://localhost:" + ServerConfigDefaults.AA_API_PORT + "/";
        final String containerName = "container.media";

        // prepare test data folder
        File testFolder = new File("testData");
        testFolder.mkdirs();
        Date now = new Date();
        Date tomorrow = new Date(now.getTime() + 1000*60*60*24);
        Date fiveDaysFromNow = new Date(now.getTime() + 1000*60*60*24*5);

        // encrypt
        // Building reduced manifest to send to AA
        final String msg = "{\n" +
                "    \"files\": [\n" +
                "        {\n" +
                "            \"path\": "+ JSONObject.quote(new File("../container/pictures_990x742/monkey_990x742.jpg").getCanonicalPath())+",\n" +
                "            \"type\": \"PABE14\",\n" +
                "            \"policy\": \"attr1\"\n" +
                "        },\n" +
                "        {\n" +
                "            \"path\": "+JSONObject.quote(new File("../container/pictures_990x742/penguins-south-georgia-island_86370_990x742er.jpg").getCanonicalPath())+",\n" +
                "            \"type\": \"PABE14\",\n" +
                "            \"policy\": \"attr1\",\n" +
                "            \"expire\": [" +
                "                {" +
                "                    \"span\": [" + tomorrow.getTime() +
                "                        , " + fiveDaysFromNow.getTime() +
                "                        ]" +
                "                }" +
                "            ]" +
                "        },\n" +
                "        {\n" +
                "            \"path\": "+JSONObject.quote(new File("../container/pictures_990x742/vatnajokull-glacier-iceland_76622_990x742er.jpg").getCanonicalPath())+",\n" +
                "            \"type\": \"PABE14\",\n" +
                "            \"policy\": \"attr1 and (attr2 or attr3)\",\n" +
                "            \"expire\": [" +
                "                {" +
                "                    \"span\": [" + tomorrow.getTime() + "]" +
                "                }" +
                "            ]" +
                "        },\n" +
                "        {\n" +
                "            \"path\": "+JSONObject.quote(new File("../container/pictures_990x742/dos-palmas-cenote-mexico_75437_990x742er.jpg").getCanonicalPath())+",\n" +
                "            \"type\": \"PABE14\",\n" +
                "            \"policy\": \"attr1 and (attr2 or attr3)\",\n" +
                "            \"expire\": [" +
                "                {" +
                "                    \"span\": [" + now.getTime() +
                "                        , " + tomorrow.getTime() +
                "                        ]" +
                "                }" +
                "            ]" +
                "        }\n" +
                "    ],\n" +
                "    \"outfile\": "+JSONObject.quote(new File(testFolder, containerName).getCanonicalPath())+",\n" +
                "    \"hidePolicy\": false," +
                "    \"owner\": {" +
                "        \"emails\": [ \"gordon.freeman@blackmesa.mil\" ]" +
                "    }" +
                "}";
        System.out.println(msg);
        final JSONObject redMan = new JSONObject(msg);
        JSONObject req;

        r = new ClientResource(l+"encrypt/1").post(redMan.toString());
        System.out.println("trigger asynchronous encryption of some files and create the container: " + r.getText());

        boolean finished = false;
        while(!finished) {
            r = new ClientResource(l+"encrypt/1").get();
            req = new JSONObject(r.getText());
            try {
                if (req.getBoolean("success") && !"processing".equals(req.getString("status"))) {
                    finished = true;
                    System.out.println("finished encryption: " + req.toString());
                } else {
                    System.out.println("unfinished encryption: " + req.toString());
                }
            } catch (JSONException e) {
                System.out.println("unfinished encryption: JSON.error: " + e.getMessage());
            }
            Thread.sleep(1000L);
        }

        // keygen part 1
        r = new ClientResource(l+"user").post("12");
        System.out.println("create uid 12: " + r.getText());

        o = new JSONObject();

        // check delete error message
        r = new ClientResource(l+"user/12/attribute/attr1").delete();
        System.out.println("delete connection between uid 12 and attribute attr1 (should fail): " + r.getText());

        // keygen part 2
        r = new ClientResource(l+"user/12/attribute/attr1").put(o);
        System.out.println("create connection between uid 12 and attribute attr1: " + r.getText());

        r = new ClientResource(l+"user/12/attribute/attr2").put(o);
        System.out.println("create connection between uid 12 and attribute attr2: " + r.getText());

        r = new ClientResource(l+"user/12/attribute/attr1").get();
        System.out.println("get connection between uid 12 and attribute attr1: " + r.getText());

        r = new ClientResource(l+"user/12/attribute/attr3").put(o);
        System.out.println("create connection between uid 12 and attribute attr3: " + r.getText());
        r = new ClientResource(l+"user/12/attribute/attr3").delete();
        System.out.println("delete connection between uid 12 and attribute attr3 (should succeed): " + r.getText());

        r = new ClientResource(l+"user/12").get();
        String privateKeyResponseString = r.getText();
        System.out.println("get user base private key with uid 12: " + privateKeyResponseString);


        // VERIFY...

        // get private key
        JSONObject privateKeyResponse = new JSONObject(privateKeyResponseString);
        byte[] privateKeyBytes = Base64.decodeBase64((String) privateKeyResponse.get("privatekey"));
        AbePrivateKey privateKey = AbePrivateKey.readFromByteArray(privateKeyBytes);

        // read container
        File containerFile = new File(testFolder, containerName);
        ContainerReader container = new ContainerReader(new FileInputStream(containerFile))
                .setDecryptor(privateKey);

        ByteArrayOutputStream out;

        // try to decrypt the first file
        out = new ByteArrayOutputStream();
        container.decrypt(0, out);
        byte[] file1Bytes = out.toByteArray();

        byte[] file1OriginalBytes = readBytes((String) ((JSONObject) ((JSONArray) redMan.get("files")).get(0)).get("path"));
        System.out.println("Matches file 1? " + Arrays.equals(file1Bytes, file1OriginalBytes));



        // VERIFY through API...

        // wait a little until all the shares are pushed
        System.out.println("Waiting 10 seconds");
        Thread.sleep(10000L);

        JSONObject userKey = new JSONObject();
        userKey.put("privateKey", privateKeyResponse.get("privatekey"));

        File outputDir =  new File(testFolder, "outputDir");
        if (outputDir.exists()) {
            File[] files = outputDir.listFiles();
            if (files != null) {
                for(File file : files) {
                    file.delete();
                }
            }
        }

        o = new JSONObject();
        o.put("container", new File(testFolder, containerName).getCanonicalPath());
        o.put("outputDirectory", outputDir.getCanonicalPath());
        o.put("user", userKey);

        r = new ClientResource(l+"decrypt/1").post(o);
        System.out.println("decrypt previously created container through the API: " + r.getText());
    }

    private static byte[] readBytes(String file) throws IOException {
        return readBytes(new File(file));
    }

    private static byte[] readBytes(File file) throws IOException {
        FileInputStream fis = new FileInputStream(file);
        byte[] out = new byte[fis.available()];
        fis.read(out);
        fis.close();
        return out;
    }

    private static byte[] readShareLocation(byte[] ctPart, int index) throws IOException {
        ByteArrayInputStream ctStream = new ByteArrayInputStream(ctPart);

        int keyLength = ctStream.read();

        ctStream.skip(keyLength);
        ctStream.read(); // N
        ctStream.read(); // K
        int locationSize = ctStream.read();
        int modSize = ctStream.read();
        ctStream.skip(modSize);

        ctStream.skip(locationSize * index);

        byte[] location = new byte[locationSize];
        ctStream.read(location);

        try {
            ctStream.close();
        } catch (IOException e) {}
        return location;
    }
}
