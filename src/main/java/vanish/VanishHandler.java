package vanish;

import edu.washington.cs.vanish.apps.VanishClientInterface;
import edu.washington.cs.vanish.conf.VanishConfiguration;
import edu.washington.cs.vanish.internal.InvalidArgumentVanishException;
import edu.washington.cs.vanish.internal.VanishException;
import edu.washington.cs.vanish.internal.metadata.VDOParams;
import edu.washington.cs.vanish.logging.LogStat;
import edu.washington.cs.vanish.logging.VanishLogger;
import edu.washington.cs.vanish.service.RemoteVanishServiceInterface;
import edu.washington.cs.vanish.util.Initializable;
import org.apache.xmlrpc.XmlRpcException;
import org.apache.xmlrpc.client.XmlRpcClient;
import org.apache.xmlrpc.client.XmlRpcClientConfigImpl;

import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class VanishHandler implements Initializable {
    private final long kRpcTimeout;
    private final int kNumRPCTries;

    private VanishConfiguration configuration;
    private VanishClientInterface baseClient;

    private Boolean is_server_local;
    private XmlRpcClient client;
    private URL sds_url;
    private VanishLogger logger = VanishLogger.getLogger("integration");

    // Used for stats:

    private final Map<String, Object> client_map;

    public VanishHandler(VanishConfiguration conf) {
        configuration = conf;
        kRpcTimeout = conf.getTimeInMillis(
                ConfigDefaults.CONF_VANISH_APPS_RPCTIMEOUT_S,
                ConfigDefaults.CONF_VANISH_APPS_RPCTIMEOUT_S_DEFAULT,
                VanishConfiguration.TimeUnit.SECONDS);
        kNumRPCTries = conf.getInt(
                ConfigDefaults.CONF_VANISH_APPS_NUMRPCTRIES,
                ConfigDefaults.CONF_VANISH_APPS_NUMRPCTRIES_DEFAULT);
        long installation_id = new Random().nextLong();
        client_map = new HashMap<String, Object>();
        client_map.put("vid", installation_id);
        client_map.put("ref", "shell");
    }

    public byte[] encapsulate(byte[] msg, VDOParams vdoParams) throws VanishException {
        final LogStat logstat = logger.logStat("VanishClientImpl.encapsulate");
        byte[] result = executeWithReturn(
                RemoteVanishServiceInterface.kVanishServiceName + ".encapsulate",
                new Object[] { client_map, msg, vdoParams.toMap() });
        logstat.end();
        return result;
    }

    public byte[] decapsulate(byte[] s) throws VanishException {
        final LogStat logstat = logger.logStat("VanishClientImpl.decapsulate");
        byte[] result = executeWithReturn(
                RemoteVanishServiceInterface.kVanishServiceName + ".decapsulate",
                new Object[] { client_map, s });
        logstat.end();
        return result;
    }

    public void refreshReadOnly(byte[] s) throws VanishException {
        throw new VanishException("not implemented");
    }

    public void refreshDeeply(byte[] s, byte[] s2, VDOParams vdoParams) throws VanishException {
        throw new VanishException("not implemented");
    }

    private byte[] executeWithReturn(String operation, Object[] params)
            throws VanishException {
        XmlRpcException last_exception = null;
        for (int i = 0; i < kNumRPCTries; ++i) {
            try {
                return (byte[])client.execute(operation, params);
            } catch (XmlRpcException e) {
                last_exception = e;
                continue;
            }
        }
        throw new VanishException("Failed after retries", last_exception);
    }

    private void executeWithoutReturn(String operation, Object[] params)
            throws VanishException {
        XmlRpcException last_exception = null;
        for (int i = 0; i < kNumRPCTries; ++i) {
            try {
                client.execute(operation, params);
                return; // done.
            } catch (XmlRpcException e) {
                last_exception = e;
                continue;
            }
        }
        throw new VanishException("Failed after retries", last_exception);
    }

    private void initConnectionToVanishServer() throws UnknownHostException {
        XmlRpcClientConfigImpl config = new XmlRpcClientConfigImpl();
        config.setEnabledForExtensions(true);
        config.setServerURL(sds_url);
        int timeout = -1;
        if (timeout > 0) {
            config.setReplyTimeout(timeout);
            config.setConnectionTimeout(timeout);
        }
        client = new XmlRpcClient();
        client.setConfig(config);

        setIsServerLocal();
    }

    private void setIsServerLocal() throws UnknownHostException {
        is_server_local = false;
        InetAddress sds_service_addr = InetAddress.getByName(
                sds_url.getHost());
        if (InetAddress.getLocalHost().equals(sds_service_addr) ||
                sds_service_addr.isLoopbackAddress()) {
            is_server_local = true;
        }
    }

    public void setVanishServiceURL(URL url) throws UnknownHostException {
        this.sds_url = url;
        initConnectionToVanishServer(); // re-initialize.
    }

//    @Override
    public void init() throws InvalidArgumentVanishException {
        assert (!isInitialized());

        // Perform some special configs.
        System.setProperty("sun.net.client.defaultConnectTimeout",
                "" + kRpcTimeout);
        System.setProperty("sun.net.client.defaultReadTimeout",
                "" + kRpcTimeout);

        try {
            initConnectionToVanishServer();
        } catch (UnknownHostException e) {
            throw new InvalidArgumentVanishException(
                    "Failed to init vanish server connection", e);
        }
    }

//    @Override
    public boolean isInitialized() {
        return client != null;
    }

//    @Override
    public void stop() throws VanishException {

    }
}