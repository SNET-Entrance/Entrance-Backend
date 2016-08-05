package integration.engine;

import com.orientechnologies.orient.core.record.impl.ODocument;
import integration.external.ExternalKeyDistributionStorage;
import net.i2p.crypto.eddsa.EdDSAEngine;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import rest.ServerConfigDefaults;
import rest.Storage;
import snet.entrance.ExpirationType;
import snet.entrance.ExpirationType2Utils;
import trabe.*;
import trabe.aes.AesEncryption;
import trabe.lw14.Lw14PrivateKeyComponent;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.locks.ReentrantLock;

import static java.util.Map.Entry;
import static rest.ServerConfigDefaults.JQ_MAIN_EVENT_INTERVAL;

/**
 * Job scheduler which uses a {@link Timer} internally to schedule different job executions
 */
public class JobQueue {
    private static JobQueue jobQueue;
    private static final Logger logger = Logger.getLogger(JobQueue.class);

    private final Timer timer = new Timer(true);
    private Date nextMainEvent;
    private Date currentMainEvent;

    /* General schedule of tasks that were retrieved from database or put in on demand */
    private Map<Date, ConcurrentHashMap<ODocument, Boolean>> queue;
    private final ReentrantLock lock = new ReentrantLock(true);

    /* Queue of task that need to be reevaluated */
    private boolean checkChangedDocumentJobScheduled = false;
    private ConcurrentLinkedQueue<ODocument> reevaluateQueue = new ConcurrentLinkedQueue<ODocument>();
    private final ReentrantLock reevaluateQueueLock = new ReentrantLock(true);

    /**
     * Put document into a queue for later re-evaluation of the document. This
     * method is meant to be called from other request threads, because it
     * puts the document into a queue and immediately returns. The queue is
     * not meant to be locked for a long time, so the execution is fast.
     *
     * @param document    Document to add and re-evaluate at a later time
     * @see #evaluateDocumentForQueue(ODocument)
     * @see #evaluateDocumentsForQueue()
     */
    public synchronized void checkDocumentForQueue(ODocument document) {
        if (document == null) return;
        reevaluateQueue.add(document);

        reevaluateQueueLock.lock();

        try {
            if (!checkChangedDocumentJobScheduled) {
                checkChangedDocumentJobScheduled = true;
                timer.schedule(new JobCheckChangedDocument(this), 5000L); // wait 5 seconds
            }
        } finally {
            reevaluateQueueLock.unlock();
        }
    }

    /**
     * Iterates over all recently changed documents (which were put into a
     * special internal queue of this object) and evaluates whether their
     * shares need to be updated.
     *
     * @see #evaluateDocumentForQueue(ODocument)
     */
    public void evaluateDocumentsForQueue() {
        logger.info("evaluateDocumentsForQueue start");

        ODocument doc;
        while((doc = reevaluateQueue.poll()) != null) {
            evaluateDocumentForQueue(doc);
        }

        reevaluateQueueLock.lock();

        try {
            if (reevaluateQueue.size() > 0) {
                // reschedule, because there was a new request in the mean time
                checkChangedDocumentJobScheduled = true;
                timer.schedule(new JobCheckChangedDocument(this), 5000L); // wait 5 seconds
            } else {
                checkChangedDocumentJobScheduled = false;
            }
        } finally {
            reevaluateQueueLock.unlock();
        }
    }

    /**
     * Adds a new or patched document to the queue for updates. It is the actual
     * implementation of the re-evaluation which is a third step beginning with
     * {@link #checkDocumentForQueue(ODocument)}. The passed document must have
     * an "expire" field. Currently, only <code>FileBag</code> database classes
     * are eligible.
     * @param document    FileBag or user attribute document
     */
    private void evaluateDocumentForQueue(ODocument document) {
        lock.lock();

        try {
            // remove currently re-checked document from the queue so that it can be re-added later
            removeDocumentFromQueue(document);

            // determine when the document updates have to be scheduled
            ConcurrentHashMap<ODocument, Boolean> currentExecutionList = new ConcurrentHashMap<ODocument, Boolean>();
            Date now = new Date();
            JobReevaluation.evaluateScheduleForTimedExpiration(document, now, nextMainEvent, currentExecutionList, queue);

            document.unload(); // reduce memory footprint

            if (currentExecutionList.size() > 0) {
                queue.put(now, currentExecutionList);
                timer.schedule(new JobInbetween(this), now);
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Remove the given document from the queue if it exists. Do nothing if it doesn't.
     * @param document    Document to check for
     */
    private void removeDocumentFromQueue(ODocument document) {
        for(Map.Entry<Date, ConcurrentHashMap<ODocument, Boolean>> dateDocs : queue.entrySet()) {
            for(Map.Entry<ODocument, Boolean> doc : dateDocs.getValue().entrySet()) {
                if(doc.getKey().getIdentity().equals(document.getIdentity())) {
                    dateDocs.getValue().remove(doc.getKey());
                }
            }
        }
    }

    /**
     * Initialize queue and schedule the first population of the queue.
     */
    public void init() {
        logger.info("init");

        lock.lock();

        try {
            if (currentMainEvent != null) {
                return; // already initialized
            }
            timer.schedule(new JobReevaluation(this), 5000L); // 5 second delay
        } finally {
            lock.unlock();
        }
    }

    /**
     * Sets the interval timestamps to the next interval and schedules the next main event
     */
    protected void rescheduleMainEvent() {
        logger.info("rescheduleMainEvent");

        lock.lock();

        try {
            if (currentMainEvent == null) {
                currentMainEvent = new Date();
            } else {
                currentMainEvent = nextMainEvent;
            }
            long now = currentMainEvent.getTime();
            nextMainEvent = new Date(now + 1000 * 60 * JQ_MAIN_EVENT_INTERVAL);

            timer.schedule(new JobReevaluation(this), nextMainEvent);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Run the actual update of all currently tracked documents for expiration
     * or immediate revocation. The given {@link Map} consists of all of those
     * documents that have either an <code>expire</code> or a <code>delete</code>
     * attribute. The value of the {@link Map} entry denotes whether the document
     * must be updated. If the value is <code>false</code>, then it must not
     * be updated or if strict, immediately revoked.
     * @param documents    {@link Map} of documents and their update strategy
     */
    protected void runUpdate(Map<ODocument, Boolean> documents) {
        // TODO: implement deletion of the "deleted DB document" (delete shares are successfully pushed)

        logger.info("#runUpdate(docs): start");

        final Storage storage = Storage.getInstance();

        final Signature signatureSign;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            signatureSign = new EdDSAEngine(md);
        } catch (NoSuchAlgorithmException e) {
            logger.error("#runUpdate: MessageDigest SHA-512 not available");
            return;
        }

        final PrivateKey sk = storage.getMasterSigningKey();

        if (sk == null) {
            logger.error("#runUpdate: No signing key available");
            return;
        }

        // logger.debug("#runUpdate: SK = " + Hex.encodeHexString(((EdDSAPrivateKey) sk).getAbyte()));

        final Mac hmac;
        try {
            hmac = Mac.getInstance("HmacSha256", "BC");
        } catch (NoSuchAlgorithmException e) {
            logger.error("#runUpdate: 'HmacSha256' is not available");
            return;
        } catch (NoSuchProviderException e) {
            logger.error("#runUpdate: BouncyCastle is not available");
            return;
        }

        SecureRandom random = new SecureRandom();

        lock.lock();

        try {
            if (documents == null) {
                return;
            }

            ExternalKeyDistributionStorage dht = ExternalKeyDistributionStorage.getInstance();
            byte[] dhtIdentifier = dht.getIdentifier().getBytes("UTF-8");

            for (Entry<ODocument, Boolean> document : documents.entrySet()) {
                ODocument doc = document.getKey();
                doc.reload();

                logger.info("#runUpdate: Scheduling " + doc.getClassName() + "@" +
                        doc.getIdentity().toString() + "    FULL: " + doc.toJSON() +
                        "   start? " + document.getValue());

                boolean delete = doc.containsField("delete") && (Boolean)doc.field("delete");

                if ("Attribute".equals(doc.getClassName())) {
                    updateAttributeExternally(doc, signatureSign, sk, dht, document.getValue() || delete, delete, hmac, random);
                } else if ("FileBag".equals(doc.getClassName())) {
                    updateFileBagExternally(doc, signatureSign, sk, dht, document.getValue() || delete, delete);
                } else {
                    logger.error("#runUpdate: unknown document class: " + doc.getClassName());
                }
            }
        } catch (UnsupportedEncodingException e) {
            logger.error("UTF-8 not supported", e);
        } finally {
            logger.info("#runUpdate(docs): done");
            lock.unlock();
        }
    }

    /**
     * Something went wrong during the current execution and the document update
     * must be retried at a later time. Remove the document from all future
     * updates that are scheduled (depending on update type).
     * @param document    Document to update
     */
    private void reschedule(ODocument document) {
        checkDocumentForQueue(document);
    }

    /**
     * Get the update jobs that are scheduled under the given date and execute them.
     * @param date    specified date/time of the jobs
     */
    protected void runUpdate(Date date) {
        logger.info("runUpdate(date) start");

        lock.lock();

        try {
            Map<ODocument, Boolean> documents = queue.get(date);
            this.runUpdate(documents);
        } finally {
            lock.unlock();
        }
    }

    /**
     * TODO: document
     * @param documents
     */
    protected void deferUpdatesToALaterPredefinedTime(Map<Date, ConcurrentHashMap<ODocument, Boolean>> documents) {
        lock.lock();

        try {
            this.reevaluateQueue = new ConcurrentLinkedQueue<ODocument>();
            this.queue = documents;
            // TODO: check if there are un-updated documents and re-add them to the new queue

            for (Entry<Date, ? extends Map<ODocument, Boolean>> doc : documents.entrySet()) {
                timer.schedule(new JobInbetween(this), doc.getKey());
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * A document and its children have expired and must be purged from the database.
     * @param storage    Storage containing a reference to the database
     * @param doc        Document to be deleted
     */
    private void deleteExpirableDocument(Storage storage, ODocument doc) {
        try {
            storage.db.begin();
            if (doc.containsField("expire")) {
                List<ODocument> expire = doc.field("expire");
                for(ODocument ts : expire) {
                    ts.delete();
                }
            }
            doc.delete();
            storage.db.commit();
        } catch (RuntimeException e) {
            logger.debug("#runUpdate: deletion of obsolete Attribute document failed");
        }
    }

    /**
     * Push an Attribute update to the specified external storage.
     *
     * @param doc              Database attribute document (Attribute class)
     * @param signatureSign    Signature algorithm
     * @param sk               Signing key
     * @param ekds             External key storage
     * @param deleteExternal   delete flag - external data must be deleted
     * @param deleteDocument   delete flag - the database document must be deleted
     *                         (presumably when the external deletion was successful)
     * @param hmac             HMAC algorithm
     * @param random           Randomness provider
     */
    private void updateAttributeExternally(ODocument doc, Signature signatureSign, PrivateKey sk,
                                           ExternalKeyDistributionStorage ekds, boolean deleteExternal,
                                           boolean deleteDocument, Mac hmac, Random random)
    {
        String exprType = doc.field("expirationType");
        String name = ((String)doc.field("name")).trim();
        String nameShort = "" + name;
        ODocument user = doc.field("user");

        byte[] secretSeed = user.field("secretSeed");
        secretSeed = Arrays.copyOf(secretSeed, 32);
        SecretKey secretSeedAsKey = new SecretKeySpec(secretSeed, "HmacSha256");

        if (name.indexOf('=') != -1) {
            nameShort = name.substring(0, name.indexOf('=')).trim();
            logger.warn("#runUpdate: Numerical attributes are currently not supported");
        }

        try {
            byte[] dhtIdentifier = ekds.getIdentifier().getBytes("UTF-8");

            AbePrivateKey secretKey = AbePrivateKey.readFromByteArray((byte[]) doc.field("data"));

            if ("TYPE1".equals(exprType)) {
                List<Lw14PrivateKeyComponent> components = secretKey.getComponents();

                Lw14PrivateKeyComponent attributeSecretKeyObj = components.get(0); // TODO: iterate if numerical

                hmac.init(secretSeedAsKey);
                hmac.update(attributeSecretKeyObj.attribute.getBytes("UTF-8"));
                hmac.update(dhtIdentifier);
                byte[] attributeBasedSeedBytes = hmac.doFinal();
                Key attributeBasedSeed = new SecretKeySpec(attributeBasedSeedBytes, hmac.getAlgorithm());

                // creating the content for to push
                ByteArrayOutputStream refreshValueStream = new ByteArrayOutputStream(512);
                signatureSign.initSign(sk);
                signatureSign.update(dhtIdentifier);
                byte dataType;
                if (deleteExternal) {
                    /**
                     * Actively/overwriting deleting the attribute key shares
                     * whenever attributes are revoked
                     */
                    dataType = 0;
                    refreshValueStream.write(dataType); // Type 0: signed deletion
                    refreshValueStream.write((byte) ServerConfigDefaults.EXP_ATTRIBUTE_REPLICATE_N);

                    signatureSign.update(dataType);
                    signatureSign.update((byte)ServerConfigDefaults.EXP_ATTRIBUTE_REPLICATE_N);
                    signatureSign.update(nameShort.getBytes("UTF-8"));
                } else {
                    /**
                     * Update attribute key shares when non-revoked
                     */
                    dataType = 1;
                    refreshValueStream.write(dataType); // Type 1: signed refresh
                    refreshValueStream.write((byte) ServerConfigDefaults.EXP_ATTRIBUTE_REPLICATE_N);
                    refreshValueStream.write((byte) AbePrivateKey.getSerializeVersion());

                    // serializing a single component
                    ByteArrayOutputStream baos = new ByteArrayOutputStream(512);
                    AbeOutputStream aos = new AbeOutputStream(baos, secretKey.getPublicKey());
                    attributeSecretKeyObj.writeToStream(aos);
                    byte[] componentBytes = baos.toByteArray();
                    aos.close();

                    hmac.init(attributeBasedSeed);
                    hmac.update(dataType);
                    byte[] encKey = hmac.doFinal("encryption".getBytes("UTF-8"));

                    byte[] iv = new byte[16];
                    random.nextBytes(iv);

                    byte[] encryptedComponentBytes = AesEncryption.encrypt(encKey, null, iv, componentBytes);
                    Arrays.fill(componentBytes, (byte)0);
                    Arrays.fill(encKey, (byte)0);

                    byte[] encodedLength = ByteBuffer.allocate(4).putInt(encryptedComponentBytes.length).array();

                    refreshValueStream.write(iv);
                    refreshValueStream.write(encodedLength);
                    refreshValueStream.write(encryptedComponentBytes);

                    signatureSign.update(dataType);
                    signatureSign.update((byte)ServerConfigDefaults.EXP_ATTRIBUTE_REPLICATE_N);
                    signatureSign.update(nameShort.getBytes("UTF-8")); // not written in the clear to the value
                    signatureSign.update(iv);
                    signatureSign.update(encodedLength);
                    signatureSign.update(encryptedComponentBytes);
                }
                byte[] signature = signatureSign.sign();

                refreshValueStream.write(signature.length);
                refreshValueStream.write(signature);

                byte[] refreshValue = refreshValueStream.toByteArray();


                byte[][] locations = new byte[ServerConfigDefaults.EXP_ATTRIBUTE_REPLICATE_N][];
                byte[] previous = new byte[0];
                for (int i = 0; i < ServerConfigDefaults.EXP_ATTRIBUTE_REPLICATE_N; i++) {
                    hmac.init(attributeBasedSeed);
                    hmac.update(previous);
                    hmac.update("location".getBytes("UTF-8"));
                    hmac.update((byte) i);
                    previous = hmac.doFinal();
                    locations[i] = Arrays.copyOf(previous, ekds.getItemIdentifierSize()); // truncate or pad with 0x00
                }

                byte[][] values = new byte[ServerConfigDefaults.EXP_ATTRIBUTE_REPLICATE_N][];

                for (int i = 0; i < ServerConfigDefaults.EXP_ATTRIBUTE_REPLICATE_N; i++) {
                    values[i] = refreshValue;
                }

                int i = ServerConfigDefaults.JQ_DHT_PUSH_RETRY;
                boolean success = false;
                while(i > 0 && !success) {
                    success = ekds.pushBulkData(locations, values);
                    i--;
                }
                if (!success) {
                    logger.warn("#runUpdate: Updates couldn't be pushed for " +
                            doc.getClassName() + "@" + doc.getIdentity().toString());
                    reschedule(doc);
                } else if (deleteDocument) {
                    logger.debug("#runUpdate: Deleting attribute when properly pushed");

                    deleteExpirableDocument(Storage.getInstance(), doc);
                }
            } else {
                logger.warn("#runUpdate: Attribute " + name + " of user " + user.getIdentity() + " uses no known expiration type");
            }
        } catch (IOException e) {
            logger.error("#runUpdate: Attribute data for external use couldn't be deserialized: " + doc.getIdentity().toString());
        } catch (InvalidKeyException e) {
            logger.error("#runUpdate: Invalid key (should have never happened)", e);
        } catch (SignatureException e) {
            logger.error("#runUpdate: Signature not properly initialized", e);
        } catch (AbeEncryptionException e) {
            logger.error("#runUpdate: Couldn't encrypt secret key component", e);
        }
    }

    /**
     * Push a FileBag update to the specified external storage.
     *
     * @param doc              Database attribute document (Attribute class)
     * @param signatureSign    Signature algorithm
     * @param sk               Signing key
     * @param ekds             External key storage
     * @param deleteExternal   delete flag - external data must be deleted
     * @param deleteDocument   delete flag - the database document must be deleted
     *                         (presumably when the external deletion was successful)
     */
    private void updateFileBagExternally(ODocument doc, Signature signatureSign, PrivateKey sk,
                                         ExternalKeyDistributionStorage ekds,
                                         boolean deleteExternal, boolean deleteDocument)
    {
        String exprType = doc.field("expirationType");
        if (ExpirationType.TYPE2.name().equals(exprType) ||
                ExpirationType.TYPE1.name().equals(exprType)) {
            // the layout and semantics of the `expirationData` for TYPE1 and TYPE2 are the same

            byte[] externalData = doc.field("expirationData");
            logger.debug("#runUpdate: externalData " + Hex.encodeHexString(externalData));

            Map<Integer, Pair<byte[], byte[]>> parsedData = ExpirationType2Utils.parseExternalData(externalData);

            // repackage shares and their locations for pushing into DHT in bulk
            byte[][] locations = new byte[parsedData.size()][];
            byte[][] shares = new byte[parsedData.size()][];
            int i = 0;
            for(Map.Entry<Integer, Pair<byte[], byte[]>> e : parsedData.entrySet()) {
                locations[i] = e.getValue().getFirst();
                byte[] share = e.getValue().getSecond();

                try {
                    signatureSign.initSign(sk);

                    ByteArrayOutputStream shareStream = new ByteArrayOutputStream();
                    byte dataType;
                    if (deleteExternal && !deleteDocument) {
                        // update share
                        dataType = 1;
                        shareStream.write(dataType); // type of data: "1 || share || signature(1 || index || share)"
                        shareStream.write(share.length); // length of share (usually small so should fit into 255)
                        shareStream.write(share);

                        signatureSign.update(dataType);
                        signatureSign.update(ByteBuffer.allocate(4).putInt(e.getKey()).array()); // Big-endian 32-bit int
                        signatureSign.update(share);
                    } else {
                        // remove share
                        dataType = 0;
                        shareStream.write(dataType); // type of data: deletion - "0 || signature(0 || index)"

                        signatureSign.update(dataType);
                        signatureSign.update(ByteBuffer.allocate(4).putInt(e.getKey()).array()); // Big-endian 32-bit int
                    }

                    byte[] signature = signatureSign.sign();

                    shareStream.write(signature.length);
                    shareStream.write(signature);

                    shares[i] = shareStream.toByteArray();

                    logger.debug("#runUpdate: signature " + Hex.encodeHexString(signature) + " for share " + Hex.encodeHexString(Arrays.copyOfRange(shares[i], 2, shares[i].length - 1 - signature.length)));
                } catch (SignatureException e1) {
                    logger.error("#runUpdate: Couldn't sign", e1);
                    continue;
                } catch (InvalidKeyException e1) {
                    logger.error("#runUpdate: Invalid signing key", e1);
                    break;
                } catch (IOException e1) {
                    logger.error("#runUpdate: This should have never happened: Couldn't write share", e1);
                    continue;
                }

                i++;
            }

            i = ServerConfigDefaults.JQ_DHT_PUSH_RETRY;
            boolean success = false;
            while(i > 0 && !success) {
                success = ekds.pushBulkData(locations, shares);
                i--;
            }
            if (!success) {
                logger.warn("#runUpdate: Updates couldn't be pushed for " +
                        doc.getClassName() + "@" + doc.getIdentity().toString());
                reschedule(doc);
            } else if (deleteDocument) {
                logger.debug("#runUpdate: Deleting fileBag when properly pushed");

                deleteExpirableDocument(Storage.getInstance(), doc);
            }
        }
    }

    /**
     * The main event is a recurring job that updates all active time spans (no starting or stopping)
     * @return Next event date and time
     */
    public Date getNextMainEvent() {
        return nextMainEvent;
    }

    /**
     * @see {@link #getNextMainEvent()}
     * @return Current event date and time
     */
    public Date getCurrentMainEvent() {
        return currentMainEvent;
    }

    public static synchronized JobQueue getInstance() {
        if (jobQueue == null) {
            jobQueue = new JobQueue();
        }
        return jobQueue;
    }

    /**
     * Sets a new JobQueue instance. This should be used for mocking the JobQueue singleton.
     * @param newJobQueue   New extending class instance
     * @return  the passed in instance
     */
    public static JobQueue setInstance(JobQueue newJobQueue) {
        jobQueue = newJobQueue;
        return jobQueue;
    }
}
