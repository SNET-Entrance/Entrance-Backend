package integration.external;

public class DummySubsystem extends ExternalKeyDistributionStorage {
    @Override
    public byte[][] getBulkData(byte[][] locations) {
        return new byte[locations.length][];
    }

    @Override
    public boolean pushBulkData(byte[][] locations, byte[][] data) {
        return false;
    }

    @Override
    public String getIdentifier() {
        return "Dummy";
    }
}
