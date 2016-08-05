package integration.engine;

import java.util.TimerTask;

public class JobCheckChangedDocument extends TimerTask {

    private final JobQueue jobQueue;

    public JobCheckChangedDocument(JobQueue jobQueue) {
        this.jobQueue = jobQueue;
    }

    @Override
    public void run() {
        jobQueue.evaluateDocumentsForQueue();
    }
}
