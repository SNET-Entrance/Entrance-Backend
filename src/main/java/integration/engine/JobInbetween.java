package integration.engine;

import java.util.Date;
import java.util.TimerTask;

public class JobInbetween extends TimerTask {

    private final JobQueue jobQueue;

    public JobInbetween(JobQueue jobQueue) {
        this.jobQueue = jobQueue;
    }

    @Override
    public void run() {
        jobQueue.runUpdate(new Date(this.scheduledExecutionTime()));
    }
}
