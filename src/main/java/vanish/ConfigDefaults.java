package vanish;

public class ConfigDefaults {
    public static final String WEBAPPS_CONFIG_FILE = "integration.properties";

    public static final String CONF_VANISH_APPS_NUMRPCTRIES =
            "vanish.apps.numrpctries";
    public static final int CONF_VANISH_APPS_NUMRPCTRIES_DEFAULT = 1;

    public static final String CONF_VANISH_APPS_RPCTIMEOUT_S =
            "vanish.apps.rpctimeout_s";
    public static final int CONF_VANISH_APPS_RPCTIMEOUT_S_DEFAULT = 600;

    public static final String CONF_VANISH_APPS_VANISHURL =
            "vanish.apps.vanishurl";
    public static final String CONF_VANISH_APPS_VANISHURL_DEFAULT =
            "http://localhost:" +
                    edu.washington.cs.vanish.util.Defaults.CONF_VANISH_PORT_DEFAULT +
                    "/xmlrpc";

    public static final String CONF_VANISH_APPS_INSTALLATION_ID =
            "vanish.apps.vanishid";
    // No default value. Must be generated automatically. Shouldn't be edited
    // in the config file.
}
