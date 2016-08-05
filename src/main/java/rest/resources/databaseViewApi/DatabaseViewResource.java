package rest.resources.databaseViewApi;

import com.github.mustachejava.DefaultMustacheFactory;
import com.github.mustachejava.Mustache;
import com.github.mustachejava.MustacheFactory;
import com.orientechnologies.orient.core.metadata.schema.OClass;
import com.orientechnologies.orient.core.record.impl.ODocument;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.restlet.data.CharacterSet;
import org.restlet.data.Language;
import org.restlet.data.MediaType;
import org.restlet.representation.StringRepresentation;
import org.restlet.resource.Get;
import org.restlet.resource.ServerResource;
import trabe.AbePrivateKey;
import rest.Storage;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class DatabaseViewResource extends ServerResource {

    private static Mustache template = null;

    @Get
    public StringRepresentation view() throws IOException {
        if (template == null) {
            InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream("dbview.tpl.html");
            String templateString = IOUtils.toString(is, "UTF-8");
            MustacheFactory factory = new DefaultMustacheFactory();
            template = factory.compile(new BufferedReader(new StringReader(templateString)), "dbview");
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintWriter writer = new PrintWriter(baos);
        template.execute(writer, getDbData());
        writer.close();

        return new StringRepresentation(
                new String(baos.toByteArray(), "UTF-8"),
                MediaType.TEXT_HTML,
                Language.ENGLISH,
                CharacterSet.UTF_8);
    }

    private Context getDbData() {
        Storage storage = Storage.getInstance();

        ArrayList<Class> classes = new ArrayList<Class>();

        for (OClass oClass : storage.db.getMetadata().getSchema().getClasses()) {
            ArrayList<Instance> instances = new ArrayList<Instance>();

            for (ODocument oDocument : storage.db.browseClass(oClass.getName())) {
                ArrayList<KeyValue> document = new ArrayList<KeyValue>();

                for (Map.Entry<String, Object> e : oDocument.toMap().entrySet()) {
                    String value = null;
                    if (e.getValue() instanceof AbePrivateKey){
                        try {
                            value = Base64.encodeBase64String(((AbePrivateKey) e.getValue()).getAsByteArray());
                        } catch (IOException e1) {
                            value = "<Exception>";
                            e1.printStackTrace();
                        }
                    } else if (e.getValue() instanceof cpabe.AbePrivateKey){
                        value = e.getValue().toString();
                    } else if (e.getValue() instanceof byte[]){
                        value = Hex.encodeHexString((byte[])e.getValue());
                    } else if (e.getValue() == null){
                        value = "<null>";
                    } else {
                        value = e.getValue().toString();
                    }

                    document.add(new KeyValue(e.getKey(), value));
                }

                instances.add(new Instance(document));
            }

            classes.add(new Class(instances, oClass.getName()));
        }

        return new Context(classes);
    }

    static class Context {
        public final List<Class> classes;

        public Context(List<Class> classes) {
            this.classes = classes;
        }
    }

    static class Class{
        public final List<Instance> instances;
        public final String name;

        public Class(List<Instance> instances, String name) {
            this.instances = instances;
            this.name = name;
        }

        public int numberOfInstances() {
            return instances.size();
        }
    }

    static class Instance {
        public final List<KeyValue> keyValues;

        public Instance(List<KeyValue> keyValues) {
            this.keyValues = keyValues;
        }
    }

    static class KeyValue {
        public final String key;
        public final String value;

        public KeyValue(String key, String value) {
            this.key = key;
            this.value = value;
        }
    }
}
