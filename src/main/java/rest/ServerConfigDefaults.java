package rest;

import de.uka.tm.jkad.framework.JKad;
import integration.external.ShexSubsystem;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;

public class ServerConfigDefaults {

    public enum ExternalKeyDistributionStorageProvider {
        DUMMY,
        VUZE,
        JKAD /* cannot be used without BEP 44 and not implemented */,
        SHEX
    }

    /**
     * Disables reading the configuration file and persisting it. (e.g. for testing)
     */
    public static final boolean LOAD_STORE_CONFIG = true;

    /**
     * Attribute authority port for REST service
     */
    public static int AA_API_PORT = 8095;

    /**
     * All data can be either stored in memory (and lost after closing the
     * authority server) or persisted in a folder on the file system to
     * use the same data across multiple executions of the authority.
     */
    public static boolean DB_USE_MEMORY = true;

    /**
     * Name of the database (orientDB and folder in file system).
     * Not to be used as path.
     */
    public static String DB_FOLDER_LOCATION = "attributeAuthorityDB";

    /**
     * Add a route to a readonly database viewer under <code>http://SERVER:PORT/dbview</code>
     */
    public static boolean DB_VIEW = true;

    /**
     * Maximum number of users allowed throughout the system lifetime after the
     * initial setup.
     */
    public static int ABE_MAX_USERS = 15;

    /**
     * The preferred external key storage service. Legal values are shown in
     * {@link rest.ServerConfigDefaults.ExternalKeyDistributionStorageProvider} and are:
     * <ul>
     *     <li>"DUMMY"</li>
     *     <li>"VUZE"</li>
     *     <li>"JKAD"</li>
     *     <li>"SHEX"</li>
     * </ul>
     */
    public static ExternalKeyDistributionStorageProvider EKDS = ExternalKeyDistributionStorageProvider.DUMMY;

    /**
     * <strong>Job Queue:</strong> Time interval between two main update
     * events in minutes
     */
    public static int JQ_MAIN_EVENT_INTERVAL = 60 * 4;

    /**
     * <strong>Job Queue:</strong> Minimal allowed time interval between two
     * update events outside of main updates in minutes
     */
    public static int JQ_BETWEEN_EVENT_SCHEDULING_GRANULARITY = 20; // 20 minutes

    /**
     * <strong>Job Queue:</strong> How many times a DHT push operation is
     * tried until an error is determined and/or the push rescheduled.
     */
    public static int JQ_DHT_PUSH_RETRY = 3;

    /**
     * <strong>JKad DHT:</strong> Class name of the DHT implementation (default
     * is mainline)
     */
    public static String JKAD_FACT_NAME = JKad.FULL_FACT_NAME_BASELINE; // TODO: load/store

    /**
     * <strong>JKad DHT:</strong> A DHT needs some kind of known location to
     * bootstrap some initial nodes to find a way into the swarm and build up
     * a list of neighbor nodes.
     */
    public static String JKAD_BOOTSTRAP_HOST = "router.utorrent.com:6881;router.bittorrent.com:6881"; // TODO: load/store

    /**
     * <strong>JKad DHT:</strong> IP address to accept connections from. Use
     * <code>null</code> if connections from every IP (0.0.0.0) should be
     * accepted.
     */
    public static String JKAD_LISTEN_IP = null; // TODO: load/store

    /**
     * <strong>JKad DHT:</strong> UDP Port to listen on for new connections.
     */
    public static int JKAD_PORT = 8097; // TODO: load/store

    /**
     * <strong>Signature:</strong> Signature definition (non-changeable)
     */
    public static final String EDDSA_SPECIFICATION_STRING = "ed25519-sha-512";

    /**
     * <strong>Dynamic Attributes:</strong> Amount of direct replications for
     * an attribute without threshold sharing. Should not be larger than 255.
     */
    public static int EXP_ATTRIBUTE_REPLICATE_N = 7;

    /**
     * URI used for {@link ShexSubsystem}.
     */
    public static String SHEX_URI = "http://localhost:5000/";



    private static final String CONFIG_FILE = "config.properties";
    private static final String AA_API_PORT_KEY = "aaApiPort";
    private static final String DB_USE_MEMORY_KEY = "useMemoryDb";
    private static final String DB_FOLDER_LOCATION_KEY = "folderDbPath";
    private static final String DB_VIEW_KEY = "dbView";
    private static final String ABE_MAX_USERS_KEY = "abeMaxUsers";
    private static final String EKDS_KEY = "externalKeyStorageProvider";
    private static final String JQ_MAIN_EVENT_INTERVAL_KEY = "mainEventInterval";
    private static final String JQ_BETWEEN_EVENT_SCHEDULING_GRANULARITY_KEY = "betweenMainEventGranularity";
    private static final String JQ_DHT_PUSH_RETRY_KEY = "jqPushRetry";
    private static final String EXP_ATTRIBUTE_REPLICATE_N_KEY = "replicateAttributeNTimes";
    private static final String SHEX_URI_KEY = "shexUri";

    /**
     * Write the configuration to a file <i>config.properties</i>.
     * @return  File was successfully written
     */
    public static boolean writeConfig() {
        if (!LOAD_STORE_CONFIG) {
            return false;
        }

        Properties prop = new Properties();
        prop.setProperty(AA_API_PORT_KEY, ""+AA_API_PORT);
        prop.setProperty(DB_USE_MEMORY_KEY, ""+ DB_USE_MEMORY);
        prop.setProperty(DB_FOLDER_LOCATION_KEY, DB_FOLDER_LOCATION);
        prop.setProperty(DB_VIEW_KEY, ""+DB_VIEW);
        prop.setProperty(ABE_MAX_USERS_KEY, ""+ABE_MAX_USERS);
        prop.setProperty(EKDS_KEY, EKDS.name());
        prop.setProperty(JQ_MAIN_EVENT_INTERVAL_KEY, ""+JQ_MAIN_EVENT_INTERVAL);
        prop.setProperty(JQ_BETWEEN_EVENT_SCHEDULING_GRANULARITY_KEY, ""+JQ_BETWEEN_EVENT_SCHEDULING_GRANULARITY);
        prop.setProperty(JQ_DHT_PUSH_RETRY_KEY, ""+JQ_DHT_PUSH_RETRY);
        prop.setProperty(EXP_ATTRIBUTE_REPLICATE_N_KEY, ""+EXP_ATTRIBUTE_REPLICATE_N);
        prop.setProperty(SHEX_URI_KEY, ""+SHEX_URI);

        try {
            prop.store(new FileOutputStream(new File(CONFIG_FILE)), "");
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    /**
     * Read the configuration from a file <i>config.properties</i>.
     * @return  File was successfully read
     */
    public static boolean readConfig() {
        if (!LOAD_STORE_CONFIG) {
            return false;
        }

        Properties prop = new Properties();
        try {
            prop.load(new FileInputStream(new File(CONFIG_FILE)));
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }

        if (prop.containsKey(AA_API_PORT_KEY))
            AA_API_PORT = Integer.parseInt(prop.getProperty(AA_API_PORT_KEY));
        if (prop.containsKey(DB_USE_MEMORY_KEY))
            DB_USE_MEMORY = Boolean.parseBoolean(prop.getProperty(DB_USE_MEMORY_KEY));
        if (prop.containsKey(DB_FOLDER_LOCATION_KEY))
            DB_FOLDER_LOCATION = prop.getProperty(DB_FOLDER_LOCATION_KEY);
        if (prop.containsKey(DB_VIEW_KEY))
            DB_VIEW = Boolean.parseBoolean(prop.getProperty(DB_VIEW_KEY));
        if (prop.containsKey(ABE_MAX_USERS_KEY))
            ABE_MAX_USERS = Integer.parseInt(prop.getProperty(ABE_MAX_USERS_KEY));
        if (prop.containsKey(EKDS_KEY))
            EKDS = ExternalKeyDistributionStorageProvider.valueOf(prop.getProperty(EKDS_KEY));
        if (prop.containsKey(JQ_MAIN_EVENT_INTERVAL_KEY))
            JQ_MAIN_EVENT_INTERVAL = Integer.parseInt(prop.getProperty(JQ_MAIN_EVENT_INTERVAL_KEY));
        if (prop.containsKey(JQ_BETWEEN_EVENT_SCHEDULING_GRANULARITY_KEY))
            JQ_BETWEEN_EVENT_SCHEDULING_GRANULARITY = Integer.parseInt(prop.getProperty(JQ_BETWEEN_EVENT_SCHEDULING_GRANULARITY_KEY));
        if (prop.containsKey(JQ_DHT_PUSH_RETRY_KEY))
            JQ_DHT_PUSH_RETRY = Integer.parseInt(prop.getProperty(JQ_DHT_PUSH_RETRY_KEY));
        if (prop.containsKey(EXP_ATTRIBUTE_REPLICATE_N_KEY))
            EXP_ATTRIBUTE_REPLICATE_N = Integer.parseInt(prop.getProperty(EXP_ATTRIBUTE_REPLICATE_N_KEY));
        if (prop.containsKey(SHEX_URI_KEY))
            SHEX_URI = prop.getProperty(SHEX_URI_KEY);

        return true;
    }
}
