package integration.external;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.restlet.Client;
import org.restlet.Request;
import org.restlet.Response;
import org.restlet.data.Method;
import org.restlet.representation.StringRepresentation;
import org.restlet.resource.ResourceException;
import rest.ServerConfigDefaults;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Shex is a lightweight storage system
 */
public class ShexSubsystem extends ExternalKeyDistributionStorage {
    private static final Logger logger = Logger.getLogger(ShexSubsystem.class);
    private static ShexSubsystem shexSubsystem;

    public byte[][] getBulkData(byte[][] locations) {
        logger.info("#getBulk: " + locations.length);

        byte[][] responses = new byte[locations.length][];
        int succeeded = 0;
        String protocol = ServerConfigDefaults.SHEX_URI.split(":")[0];
        for (int i = 0; i < locations.length; i++) {
            try {
                Client c = new Client(protocol);
                Response response = c.handle(new Request(
                        Method.GET,
                        new URI(ServerConfigDefaults.SHEX_URI + Base64.encodeBase64URLSafeString(locations[i])).toString()
                ));

                if (response == null || response.getStatus() == null) {
                    logger.warn("#getBulk: no response or status");
                } else {
                    int statusCode = response.getStatus().getCode();
                    if (statusCode == 200) {
                        responses[i] = (new Base64(true)).decode(response.getEntityAsText());
                        logger.debug("#getBulk: Response " + i + ": " + Hex.encodeHexString(responses[i]) + "@" + Hex.encodeHexString(locations[i]));
                        succeeded++;
                    } else {
                        logger.debug("#getBulk: Request for " + i + " failed with status " + statusCode);
                    }
                }
            } catch (ResourceException e) {
                logger.error("#getBulk: resource error", e);
            } catch (URISyntaxException e) {
                logger.error("#getBulk: URI invalid", e);
            }
        }

        logger.info("#getBulk: done, succeeded = " + succeeded + "/" + locations.length);
        return responses;
    }

    public boolean pushBulkData(byte[][] locations, byte[][] data) {
        logger.info("#pushBulk: " + locations.length);

        int succeeded = 0;
        String protocol = ServerConfigDefaults.SHEX_URI.split(":")[0];
        for (int i = 0; i < locations.length; i++) {
            try {
                logger.debug("#pushBulk: Data " + i + ": " + Hex.encodeHexString(data[i]) + "@" + Hex.encodeHexString(locations[i]));
                Client c = new Client(protocol);
                Response response = c.handle(new Request(
                        Method.PUT,
                        new URI(ServerConfigDefaults.SHEX_URI + Base64.encodeBase64URLSafeString(locations[i])).toString(),
                        new StringRepresentation(Base64.encodeBase64URLSafeString(data[i]))
                ));

                if (response == null || response.getStatus() == null) {
                    logger.warn("#pushBulk: no response or status");
                } else {
                    int statusCode = response.getStatus().getCode();
                    if (statusCode == 200) {
                        succeeded++;
                    } else {
                        logger.debug("#pushBulk: Request for " + i + " failed with status " + statusCode);
                    }
                }
            } catch (URISyntaxException e) {
                logger.error("#pushBulk: unknown URI", e);
            } catch (ResourceException e) {
                logger.error("#getBulk: resource error", e);
            }
        }

        logger.info("#pushBulk: done, succeeded = " + succeeded + "/" + locations.length);
        return succeeded == locations.length;
    }

    @Override
    public String getIdentifier() {
        return "Shex";
    }

    public static ShexSubsystem getInstance() {
        if (shexSubsystem == null) {
            shexSubsystem = new ShexSubsystem();
        }
        return shexSubsystem;
    }

    public static ShexSubsystem setInstance(ShexSubsystem shexSubsystemNew) {
        shexSubsystem = shexSubsystemNew;
        return shexSubsystem;
    }
}
