package integration.external;

import de.uka.tm.jkad.framework.Hash;
import de.uka.tm.jkad.framework.JKad;
import de.uka.tm.jkad.framework.KademliaPeer;
import de.uka.tm.jkad.framework.exceptions.JKadException;
import de.uka.tm.jkad.framework.exceptions.NetworkException;
import de.uka.tm.jkad.framework.transaction.BootstrapTransaction;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import rest.ServerConfigDefaults;

/**
 * Establishes a connection to the Mainline DHT through JKad and provides
 * convenience methods for pushing and querying data. It needs BEP 44
 * in order to store actual data in the DHT.
 *
 * <strong>JKad is not yet fully implemented</strong>
 */
public class JkadSubsystem extends ExternalKeyDistributionStorage {
    private static JkadSubsystem jkadSubsystem;
    private static final Logger logger = Logger.getLogger(JkadSubsystem.class);

    private JKad jKad;
    private KademliaPeer<?> peer;

    private JkadSubsystem() {
        logger.info("JKad (Starting...)");

        this.jKad = JKad.getInstance();
        try {
            peer = (KademliaPeer<?>) jKad.createKademliaPeer(
                    ServerConfigDefaults.JKAD_FACT_NAME,
                    ServerConfigDefaults.JKAD_LISTEN_IP,
                    ServerConfigDefaults.JKAD_PORT,
                    null);
        } catch (JKadException e) {
            logger.error("Couldn't create DHT peer", e);
            return;
        }

        try {
            Hash id = peer.getID();
            logger.info("JKad id: " + id.toString());
            logger.info("Starting DHT peer...");
            peer.start();
            logger.info("Started.");

            String[] bootstrapServers = ServerConfigDefaults.JKAD_BOOTSTRAP_HOST.split(";");
            for (String bootstrap : bootstrapServers) {
                logger.info("Bootstrapping to peer " + bootstrap + "...");
                BootstrapTransaction.BootstrapTransactionResult result = peer.bootstrap(bootstrap, 10000);
                logger.info("Bootstrapping " + (result != null && result.wasSuccessful() ? "successful." : "unsuccessfull!"));
                if (result != null && result.wasSuccessful())
                    break;
            }
        } catch (NetworkException e) {
            logger.error("Unable to start peer due to network problems. " +
                    "Do you have internet access?", e);
        }
    }

    public String getIdentifier() {
        return "JKadDHT";
    }

    /**
     * Get multiple data items from the DHT as a bulk operation. Each element
     * from the resulting array corresponds to each element from the given array.
     * @param locations    hashes to push the data to
     * @return  Data array or null if there was an error (which was probably due
     *          to Vanish-Vuze/JKad connection issue)
     */
    public byte[][] getBulkData(byte[][] locations) {
        String s = "";
        for(byte[] loc : locations) {
            s += "\n" + Hex.encodeHexString(loc);
        }
        logger.debug("#getBulkData: " + s);

        logger.error("JKad is not implemented");
        return null;
    }

    /**
     * Push multiple data items to the DHT as a bulk operation. Each element
     * from the <code>locations</code> array corresponds to each element
     * from the <code>data</code> array.
     * @param locations    Locations to push the data to
     * @param data         Data array that needs to be pushed
     * @return Success operation
     */
    public boolean pushBulkData(byte[][] locations, byte[][] data) {
        String s = "";
        for(byte[] loc : locations) {
            s += "\n  " + Hex.encodeHexString(loc);
        }
        logger.debug("#pushBulkData: " + s);

        logger.error("JKad is not implemented");
        return false;
    }

    public static JkadSubsystem getInstance() {
        if (jkadSubsystem == null) {
            jkadSubsystem = new JkadSubsystem();
        }
        return jkadSubsystem;
    }

    public static JkadSubsystem setInstance(JkadSubsystem dhtSubsystemNew) {
        jkadSubsystem = dhtSubsystemNew;
        return jkadSubsystem;
    }
}
