package integration.engine;

import com.orientechnologies.orient.core.record.impl.ODocument;
import org.apache.log4j.Logger;
import rest.ServerConfigDefaults;
import rest.Storage;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Main event scheduling: Iterate over the objects in the database and check
 * whether
 *
 * <ul>
 *     <li>an update must be executed now</li>
 *     <li>an update must be executed between this and the next main events</li>
 * </ul>
 *
 * This builds two maps and gives them to the {@link JobQueue} in order for them
 * to be executed.
 * {@link #evaluateScheduleForTimedExpiration(ODocument, Date, Date, Map, Map)}
 * implements the actual functionality of the scheduling times.
 */
public class JobReevaluation extends TimerTask {
    private static final Logger logger = Logger.getLogger(JobReevaluation.class);

    private final JobQueue jobQueue;

    private static final String EXPIRE_STR = "expire";
    private static final String DELETE_STR = "delete";

    public JobReevaluation(JobQueue jobQueue) {
        this.jobQueue = jobQueue;
    }

    /**
     * <b>Main event</b><br/>
     *
     * Tasks:
     * <ul>
     *     <li>Schedule the next main event</li>
     *     <li>Iterate over all fileBags to check whether the keys have to be
     *     updated during the main event or between this main event and the
     *     next main event</li>
     * </ul>
     */
    @Override
    public void run() {
        jobQueue.rescheduleMainEvent();
        logger.info("run");

        Storage storage = Storage.getInstance();
        ConcurrentHashMap<ODocument, Boolean> applicableContainersNow = new ConcurrentHashMap<ODocument, Boolean>();
        ConcurrentHashMap<Date, ConcurrentHashMap<ODocument, Boolean>> inBetweenSchedules = new ConcurrentHashMap<Date, ConcurrentHashMap<ODocument, Boolean>>();

        Date now = jobQueue.getCurrentMainEvent();
        Date next = jobQueue.getNextMainEvent();
        for(ODocument container : storage.db.browseClass("Container")) {
            List<ODocument> fileBags = container.field("fileBags");
            if (fileBags == null) {
                logger.warn("#run: no fileBags for container " + container.field("@rid") + " (" + container.getIdentity() + ")");
                continue;
            }
            for(ODocument fileBag : fileBags) {
                boolean delete = fileBag.containsField(DELETE_STR) && (Boolean)fileBag.field(DELETE_STR);
                if (delete) {
                    applicableContainersNow.put(fileBag, false);
                } else if (fileBag.containsField(EXPIRE_STR)) {
                    evaluateScheduleForTimedExpiration(fileBag, now, next, applicableContainersNow, inBetweenSchedules);
                }
            }
        }

        for(ODocument attribute : storage.db.browseClass("Attribute")) {
            boolean delete = attribute.containsField(DELETE_STR) && (Boolean)attribute.field(DELETE_STR);
            if (delete) {
                applicableContainersNow.put(attribute, false);
            } else if (attribute.containsField(EXPIRE_STR)) {
                evaluateScheduleForTimedExpiration(attribute, now, next, applicableContainersNow, inBetweenSchedules);
            }
        }

        jobQueue.deferUpdatesToALaterPredefinedTime(inBetweenSchedules);
        jobQueue.runUpdate(applicableContainersNow);
    }

    /**
     * Evaluate whether the update for the given document needs to be executed
     * <code>now</code> (put into the <code>current</code> map) or between
     * <code>now</code> and <code>next</code> (put into <code>later</code>).
     *
     * @param document    Container or user attribute which may need updating
     * @param now         Current time
     * @param next        Next main event time (general document update)
     * @param current     Map of documents that have to be updated <code>now</code>
     * @param later       Map of documents that have to be updated between
     *                    <code>now</code> and <code>next</code>
     */
    protected static void evaluateScheduleForTimedExpiration(ODocument document,
                                                             Date now, Date next,
                                                             Map<ODocument, Boolean> current,
                                                             Map<Date, ConcurrentHashMap<ODocument, Boolean>> later)
    {
        logger.info("evaluateScheduleForTimedExpiration");

        List<ODocument> timeSlots = document.field(EXPIRE_STR);

        Date earliest = null;
        Date latest = null;
        boolean scheduledNow = false;
        for(ODocument timeSlot : timeSlots) {
            if (current != null && !scheduledNow && checkTimeInTimeSpan(timeSlot, now)) {
                current.put(document, true);
                scheduledNow = true;
            }

            if (checkTimeSpanEndsBetweenTimes(timeSlot, now, next)) {
                if (timeSlot.containsField("strict") && (Boolean)timeSlot.field("strict")) {
                    Date cLatest = timeSlot.field("end");
                    if (latest == null || latest.before(cLatest)) {
                        latest = cLatest;
                    }
                }
            }

            if (checkTimeSpanBeginsBetweenTimes(timeSlot, now, next)) {
                Date cEarliest = timeSlot.field("start");
                if (earliest == null || earliest.after(cEarliest)) {
                    earliest = cEarliest;
                }
            }
        }

        if (earliest != null || latest != null) {
            boolean earliestSlotFound = false;
            boolean latestSlotFound = false;
            long granularity = ServerConfigDefaults.JQ_BETWEEN_EVENT_SCHEDULING_GRANULARITY * 60 * 1000;
            for(Map.Entry<Date, ? extends Map<ODocument, Boolean>> slot : later.entrySet()) {
                Date time = slot.getKey();
                if (!earliestSlotFound && earliest != null && checkDateDistanceLessThanMax(time, earliest, granularity)) {
                    slot.getValue().put(document, true);
                    earliestSlotFound = true;
                }
                if (!latestSlotFound && latest != null && checkDateDistanceLessThanMax(time, latest, granularity)) {
                    slot.getValue().put(document, false);
                    latestSlotFound = true;
                }
            }

            if (!earliestSlotFound && earliest != null) {
                ConcurrentHashMap<ODocument, Boolean> singleList = new ConcurrentHashMap<ODocument, Boolean>(1);
                singleList.put(document, true);
                later.put(earliest, singleList);
            }

            if (!latestSlotFound && latest != null) {
                ConcurrentHashMap<ODocument, Boolean> singleList = new ConcurrentHashMap<ODocument, Boolean>(1);
                singleList.put(document, false);
                later.put(latest, singleList);
            }
        }
    }

    protected static boolean checkTimeInTimeSpan(ODocument timeSpan, Date time) {
        // TODO: check if strict and if it is not then relax the scheduling a bit
        Date start = timeSpan.field("start");
        if (start.before(time)) {
            if (timeSpan.containsField("end")) {
                Date end = timeSpan.field("end");
                return time.before(end);
            }
            return true;
        }
        return false;
    }

    protected static boolean checkTimeSpanBeginsBetweenTimes(ODocument timeSpan, Date bStart, Date bEnd) {
        // TODO: check if strict and if it is not then relax the scheduling a bit
        Date start = timeSpan.field("start");
        return start.after(bStart) && start.before(bEnd);
    }

    protected static boolean checkTimeSpanEndsBetweenTimes(ODocument timeSpan, Date bStart, Date bEnd) {
        if (!timeSpan.containsField("end")) {
            return false;
        }
        Date end = timeSpan.field("end");
        return end.after(bStart) && end.before(bEnd);
    }

    /**
     *
     * @param d1     Date
     * @param d2     other Date
     * @param max    Maximum allowed difference in milliseconds
     * @return  Whether the difference between the dates is smaller than the specified maximal difference
     */
    protected static boolean checkDateDistanceLessThanMax(Date d1, Date d2, long max) {
        return Math.abs(d1.getTime() - d2.getTime()) < max;
    }
}
