package integration.external;

import edu.washington.cs.vanish.conf.VanishConfiguration;
import edu.washington.cs.vanish.internal.backend.TooManySharesLostVanishException;
import edu.washington.cs.vanish.internal.backend.VanishBackendException;
import edu.washington.cs.vanish.internal.backend.VanishBackendInterface;
import edu.washington.cs.vanish.internal.backend.rpcimpl.RPCVanishBackendImpl;
import edu.washington.cs.vanish.logging.VanishLogger;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;

import java.util.concurrent.locks.ReentrantLock;

/**
 * Establishes a connection to the VuzeDHT and provides convenience methods for
 * pushing and querying data.
 */
public class VuzeSubsystem extends ExternalKeyDistributionStorage {
    private static VuzeSubsystem vuzeSubsystem;
    private static final Logger logger = Logger.getLogger(VuzeSubsystem.class);

    private VanishBackendInterface vanishBackend;

    private VuzeSubsystem() {
        logger.info("Vuze (Starting...)");

        try {
            vanishBackend = new RPCVanishBackendImpl(new VanishConfiguration(), VanishLogger.getLogger(VuzeSubsystem.class.toString()));
            vanishBackend.init();
        } catch (edu.washington.cs.vanish.internal.VanishException e) {
            logger.error("failed to instantiate/init RPCVanishBackendImpl", e);
        }
    }

    public String getIdentifier() {
        return "VuzeDHT";
    }

    private final ReentrantLock vanishLock = new ReentrantLock();

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

        vanishLock.lock();
        try {
            return vanishBackend.getShares(locations, locations.length); // TODO: proper threshold
        } catch (VanishBackendException e) {
            logger.error("Connection issue during getShares (Vanish-Vuze)", e);
        } catch (TooManySharesLostVanishException e) {
            logger.error("Too many shares lost (Vanish-Vuze)", e);
        } finally {
            vanishLock.unlock();
        }
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

        vanishLock.lock();
        try {
            vanishBackend.pushShares(data, locations);
        } catch (VanishBackendException e) {
            logger.error("Couldn't push to Vanish-Vuze", e);
            return false;
        } finally {
            vanishLock.unlock();
        }
        return true;
    }

    public boolean alive() {
        // TODO: extend to see if a connection is available
        return vanishBackend != null && vanishBackend.isInitialized();
    }

    public static VuzeSubsystem getInstance() {
        if (vuzeSubsystem == null) {
            vuzeSubsystem = new VuzeSubsystem();
        }
        return vuzeSubsystem;
    }

    public static VuzeSubsystem setInstance(VuzeSubsystem vuzeSubsystemNew) {
        vuzeSubsystem = vuzeSubsystemNew;
        return vuzeSubsystem;
    }
}
