package integration.external;

import rest.ServerConfigDefaults;

public abstract class ExternalKeyDistributionStorage {
    public abstract byte[][] getBulkData(byte[][] locations);

    public abstract boolean pushBulkData(byte[][] locations, byte[][] data);

    public abstract String getIdentifier();

    /**
     * Identifier size in bytes
     * @return 20
     */
    public int getItemIdentifierSize() {
        return 20;
    }

    public static ExternalKeyDistributionStorage getInstance() {
        switch (ServerConfigDefaults.EKDS) {
            case DUMMY:
                return new DummySubsystem();
            case VUZE:
                return VuzeSubsystem.getInstance();
            case JKAD:
                return JkadSubsystem.getInstance();
            case SHEX:
                return ShexSubsystem.getInstance();
            default:
                throw new RuntimeException("Unknown ExternalKeyDistributionStorage: " + ServerConfigDefaults.EKDS);
        }
    }
}
