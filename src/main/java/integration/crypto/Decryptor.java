package integration.crypto;

import com.tiemens.secretshare.exceptions.SecretShareException;
import integration.FileOverwriteMitigation;
import integration.external.ExternalKeyDistributionStorage;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import rest.ServerConfigDefaults;
import snet.entrance.*;
import trabe.AbeInputStream;
import trabe.AbePrivateKey;
import trabe.aes.AesDecryptionException;
import trabe.aes.AesEncryption;
import trabe.lw14.Lw14PrivateKeyComponent;
import trabe.lw14.Lw14Util;
import trabe.policy.PolicyParsing;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.*;
import java.util.regex.Pattern;

public class Decryptor extends Thread {
    private String containerPath;
    private String outputPath;
    private String privateKey;
    private String secretSeed;
    private boolean overwriteFiles;
    private boolean checkExternal;

    private static final Logger logger = Logger.getLogger(Decryptor.class);

    /**
     * Decrypt the passed container from specified path into the passed output directory.
     * @param containerPath    Container to load from
     * @param outputPath       Resulting files to write to
     * @param privateKey       User private key (incl. attribute keys) as Base 64 encoded string
     * @param secretSeed       User secret seed as Base 64 encoded string
     * @param checkExternal    Require to always check if there are attribute secret keys available
     */
    public Decryptor(String containerPath, String outputPath, String privateKey, String secretSeed, boolean overwriteFiles, boolean checkExternal) {
        this.containerPath = containerPath;
        this.outputPath = outputPath;
        this.privateKey = privateKey;
        this.secretSeed = secretSeed;
        this.overwriteFiles = overwriteFiles;
        this.checkExternal = checkExternal;
    }

    public boolean decrypt() {
        File containerFile = new File(containerPath);
        File outputDirFile = new File(outputPath);

        if (!outputDirFile.exists() && !outputDirFile.mkdirs()) {
            logger.error("#dec: Couldn't create output directory");
            return false;
        }

        if (!containerFile.exists()) {
            logger.error("#dec: Container file doesn't exist");
            return false;
        }

        AbePrivateKey privateKey = null;
        try {
            privateKey = AbePrivateKey.readFromByteArray(Base64.decode(this.privateKey));
        } catch (IOException e) {
            logger.error("#dec: Private key couldn't be read", e);
            return false;
        }

        Signature signatureVerify = null;
        PublicKey pk = null;
        byte[] pkBytes = privateKey.getAdditionalData("authorityVerifyKey");
        if (pkBytes == null) {
            logger.warn("#decrypt: Private key doesn't contain a master verifying key");
        } else {
            logger.debug("#decrypt: PK = " + Hex.encodeHexString(pkBytes));
            EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(ServerConfigDefaults.EDDSA_SPECIFICATION_STRING);

            EdDSAPublicKeySpec pkSpec = new EdDSAPublicKeySpec(pkBytes, spec);
            pk = new EdDSAPublicKey(pkSpec);

            try {
                signatureVerify = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
            } catch (NoSuchAlgorithmException e) {
                logger.warn("#decrypt: MessageDigest SHA-512 not available", e);
            }
        }

        Set<String> notAvailableAttributes = new HashSet<String>();

        ExternalKeyDistributionStorage dht = ExternalKeyDistributionStorage.getInstance();

        final Mac hmac;
        try {
            hmac = Mac.getInstance("HmacSha256", "BC");
        } catch (NoSuchAlgorithmException e) {
            logger.error("#decrypt: 'HmacSha256' is not available");
            return false;
        } catch (NoSuchProviderException e) {
            logger.error("#decrypt: BouncyCastle is not available");
            return false;
        }

        SecretKey secretSeedAsKey = null;
        if (this.secretSeed != null && !this.secretSeed.isEmpty()) {
            byte[] secretSeed = org.apache.commons.codec.binary.Base64.decodeBase64(this.secretSeed);
            secretSeed = Arrays.copyOf(secretSeed, 32);
            secretSeedAsKey = new SecretKeySpec(secretSeed, "HmacSha256");
        }

        try {
            FileInputStream fin = new FileInputStream(containerFile);
            ContainerReader reader = new ContainerReader(fin)
                    .setDecryptor(privateKey);

            for (int i = 0; i < reader.files.size(); i++) {
                FileContainer container = reader.files.get(i);
                String fileName = container.getName();
                logger.info("#dec: file with policy: '" + container.getPolicy() + "', expiration type: " + container.getExpirationType());

                File file = new File(outputDirFile, fileName);
                if (!overwriteFiles) {
                    file = FileOverwriteMitigation.findFreeFileName(file);
                }
                FileOutputStream fos = new FileOutputStream(file);

                boolean failed = true;

                String policy = container.getPolicy();
                if (checkExternal && policy != null && !policy.isEmpty() && this.secretSeed != null) {
                    // check externally if secret attribute key updates are available

                    if (container.getType() == DataType.PABE14 && container.getPublicPABEKey() != null) {
                        includeAttributeInPrivateKeyForPABE14(policy, privateKey, notAvailableAttributes,
                                hmac, secretSeedAsKey, signatureVerify, pk, dht);
                    } else {
                        logger.error("#dec: DataType " + container.getType().name() + " is not implemented or Public key not available");
                    }
                }

                if (container.getExpirationType().needsExternalData()) {
                    // needs external data in order to do the two-step decryption

                    try {
                        // first step
                        byte[] ctPart = reader.tryDecrypt(i);

                        if (ctPart == null) {
                            logger.error("#dec: Couldn't decrypt the ctPart");
                            continue;
                        }
                        byte[] dataEncryptionKey = null;

                        if (container.getExpirationType() == ExpirationType.TYPE1) {
                            // TODO: implement (or maybe not)
                            logger.warn("#dec: TYPE1 expiration is not yet implemented");
                            continue;
                        } else if (container.getExpirationType() == ExpirationType.TYPE2) {
                            dataEncryptionKey = retrieveExternalSharesCipherTextExpirationType2(ctPart, signatureVerify, pk, dht);
                        }

                        if (dataEncryptionKey != null && reader.finalizeDecrypt(dataEncryptionKey, fos)) {
                            failed = false;
                            logger.info("#dec: SUCCESS: '" + fileName + "'");
                        } else {
                            logger.info("#dec: FAILURE (not enough attributes or no key): '" + fileName + "'");
                        }
                        fos.close();
                    } catch (IOException e) {
                        try {
                            fos.close();
                        } catch (IOException e1) {
                            logger.error("Couldn't close FileOutputStream (double-step)", e1);
                        }
                    }
                } else {
                    // decrypt directly without reliance on external data (ciphertext expiration)

                    try {
                        if (reader.decrypt(i, fos)) {
                            failed = false;
                            logger.info("#dec: SUCCESS: '" + fileName + "'");
                        } else {
                            logger.warn("#dec: FAILURE (not enough attributes or no key): '" + fileName + "'");
                        }
                        fos.close();
                    } catch (IOException e) {
                        try {
                            fos.close();
                        } catch (IOException e1) {
                            logger.error("#dec: Couldn't close FileOutputStream (single-step)", e1);
                        }
                    }
                }
                if (failed && file.exists()) {
                    if (!file.delete()) {
                        logger.error("#dec: Couldn't clean up file after failed decryption");
                    }
                }
            }

            fin.close();
        } catch (ParseException e) {
            logger.error("#dec: Couldn't parse some policy", e);
            return false;
        } catch (FileNotFoundException e) {
            logger.error("#dec: Container file couldn't be found", e);
            return false;
        } catch (IOException e) {
            // fin.close() didn't work for some reason
            logger.error("#dec: Couldn't parse some policy", e);
            return false;
        }

        return true;
    }

    private static final String of = "^([0-9]+)of([0-9]+)$";
    private static final Pattern ofPattern = Pattern.compile(of);

    private List<String> getPolicyAttributes(String policy) throws trabe.policyparser.ParseException {
        ArrayList<String> attributes = new ArrayList<String>(10);
        for(String token : PolicyParsing.parsePolicy(policy).split("\\s+")) {
            if (!ofPattern.matcher(token).matches()) {
                attributes.add(token);
            }
        }
        return attributes;
    }

    /**
     * Retrieves possibly necessary secret attribute components and includes
     * them in the passed private key. If the components couldn't be retrieved,
     * adds the unretrievable attribute name to the <code>notAvailableAttributes</code>
     * set.
     *
     * @param policy                    Policy with additional attributes
     * @param privateKey                Mutable private key
     * @param notAvailableAttributes    Mutable set of irretrievable attributes
     * @param hmac                      HMAC
     * @param secretSeedAsKey           HMAC key
     * @param signatureVerify           Signature verifier
     * @param pk                        Verify key
     * @param ekds                      External key distribution storage
     * @throws IOException
     */
    private void includeAttributeInPrivateKeyForPABE14(String policy, AbePrivateKey privateKey,
                                                       Set<String> notAvailableAttributes,
                                                       Mac hmac, SecretKey secretSeedAsKey,
                                                       Signature signatureVerify, PublicKey pk,
                                                       ExternalKeyDistributionStorage ekds)
            throws IOException
    {
        try {
            if (!Lw14Util.satisfies(policy, privateKey)) {
                // TODO: add a more clever way of retrieving dynamic attributes, because
                //       (cont) this just tries to get attributes until a set satifies the
                //       (cont) policy. It can be improved by changing the order to try
                //       (cont) smaller sets first.

                List<String> policyAttributes = getPolicyAttributes(policy);
                List<String> missingAttributes = new ArrayList<String>(10);

                for (Lw14PrivateKeyComponent component : privateKey.getComponents()) {
                    if (!policyAttributes.contains(component.attribute)) {
                        missingAttributes.add(component.attribute);
                    }
                }

                for (int j = 0; j < missingAttributes.size(); j++) {
                    String attributeName = missingAttributes.get(j);
                    if (notAvailableAttributes.contains(attributeName)) {
                        // No need to do all the communication if it weren't available in a previous iteration
                        continue;
                    }

                    // TODO: adapt how many attribute positions to try, because the number is
                    //       (cont) written to the value (see `replicated` value further down)

                    hmac.init(secretSeedAsKey);
                    hmac.update(attributeName.getBytes("UTF-8"));
                    hmac.update(ekds.getIdentifier().getBytes("UTF-8"));
                    byte[] attributeBasedKeyBytes = hmac.doFinal();
                    Key attributeBasedKey = new SecretKeySpec(attributeBasedKeyBytes, hmac.getAlgorithm());

                    byte[][] locations = new byte[ServerConfigDefaults.EXP_ATTRIBUTE_REPLICATE_N][];
                    byte[] previous = new byte[0];
                    for (int k = 0; k < ServerConfigDefaults.EXP_ATTRIBUTE_REPLICATE_N; k++) {
                        hmac.init(attributeBasedKey);
                        hmac.update(previous);
                        hmac.update("location".getBytes("UTF-8"));
                        hmac.update((byte) k);
                        previous = hmac.doFinal();
                        locations[k] = Arrays.copyOf(previous, ekds.getItemIdentifierSize()); // truncate or pad with 0x00
                    }

                    boolean componentRetrieved = false;
                    byte[][] results = ekds.getBulkData(locations);
                    for (byte[] result : results) {
                        if (result == null) {
                            logger.debug("#dec: Result missing");
                            continue;
                        }

                        ByteArrayInputStream resultBAIS = new ByteArrayInputStream(result);
                        int dataType = resultBAIS.read(); // only a byte
                        if (dataType == 1) {
                            int replicated = resultBAIS.read();
                            if (replicated == -1) {
                                logger.error("#dec: Wrong data format: end before replicated");
                                continue;
                            }
                            int serializedVersion = resultBAIS.read();
                            if (serializedVersion == -1) {
                                logger.error("#dec: Wrong data format: end before serializedVersion");
                                continue;
                            }

                            byte[] iv = new byte[16];
                            int ivBytes = resultBAIS.read(iv);
                            if (ivBytes < 16) {
                                logger.error("#dec: Too few bytes for: iv");
                                continue;
                            }

                            byte[] encodedLength = new byte[4];
                            int encodedLengthBytes = resultBAIS.read(encodedLength);
                            if (encodedLengthBytes < 4) {
                                logger.error("#dec: Too few bytes for: encodedLength");
                                continue;
                            }
                            int encodedLengthInt = ByteBuffer.wrap(encodedLength).getInt();

                            byte[] encryptedComponent = new byte[encodedLengthInt];
                            int encryptedComponentBytes = resultBAIS.read(encryptedComponent);
                            if (encryptedComponentBytes < encodedLengthInt) {
                                logger.error("#dec: Too few bytes for: encryptedComponent");
                                continue;
                            }

                            int signatureLengthBytes = resultBAIS.read();
                            if (signatureLengthBytes == -1) {
                                logger.error("#dec: Wrong data format: end before signatureLengthBytes");
                                continue;
                            }
                            byte[] signature = new byte[signatureLengthBytes];
                            int signatureBytes = resultBAIS.read(signature);
                            if (signatureBytes < signatureLengthBytes) {
                                logger.error("#dec: Too few bytes for: signature");
                                continue;
                            }

                            // FINISHED reading; now verification/decryption/deserialization

                            // TODO: check signature
                            signatureVerify.initVerify(pk);
                            try {
                                signatureVerify.update(ekds.getIdentifier().getBytes("UTF-8"));
                                signatureVerify.update((byte) 0);
                                signatureVerify.update((byte) replicated);
                                signatureVerify.update(attributeName.split("=")[0].getBytes("UTF-8"));
                                signatureVerify.update(iv);
                                signatureVerify.update(encodedLength);
                                signatureVerify.update(encryptedComponent);
                            } catch (SignatureException e) {
                                e.printStackTrace();
                            }


                            // deserialize and decrypt component
                            hmac.init(attributeBasedKey);
                            hmac.update((byte) dataType);
                            byte[] encKey = hmac.doFinal("encryption".getBytes("UTF-8"));

                            byte[] componentBytes = new byte[0];
                            try {
                                componentBytes = AesEncryption.decrypt(encKey, null, iv, encryptedComponent);
                            } catch (AesDecryptionException e) {
                                logger.error("#dec: Couldn't decrypt component", e);
                                continue;
                            }

                            ByteArrayInputStream componentBAIS = new ByteArrayInputStream(componentBytes);
                            AbeInputStream componentAIS = new AbeInputStream(componentBAIS, privateKey.getPublicKey());
                            Lw14PrivateKeyComponent component = Lw14PrivateKeyComponent.readFromStream(componentAIS, serializedVersion);
                            Arrays.fill(componentBytes, (byte) 0);

                            privateKey.getComponents().add(component);

                            componentRetrieved = true;
                            break;
                        } else if (dataType == 0) {
                            logger.debug("#dec: Remote data deleted");
                            // TODO: check signature
                        } else {
                            logger.warn("#dec: Unknown type for remote data: " + dataType);
                        }
                    }

                    if (componentRetrieved && Lw14Util.satisfies(policy, privateKey)) {
                        // the newly received and added attribute component changed the
                        // private key so that the policy can now be satisfied.

                        break;
                    }

                    if (!componentRetrieved) {
                        // no need to check again for later file bags
                        notAvailableAttributes.add(attributeName);
                    }
                }
            }
        } catch (trabe.policyparser.ParseException e) {
            logger.warn("#dec: Couldn't parse policy", e);
        } catch (InvalidKeyException e) {
            logger.error("#dec: HmacSha256 key is invalid", e);
        }
    }

    /**
     * Parse <code>ctPart</code>, look up the stored values from <code>ekds</code>
     * and reconstruct the secret for decryption of a ciphertext with TYPE2
     * expiration.
     *
     * @param ctPart             Ciphertext part
     * @param signatureVerify    Signature verifier
     * @param pk                 Verification key
     * @param ekds               External key distribution storage to ask for shares
     * @return  Reconstructed secret to pass into
     *          {@link ContainerReader#finalizeDecrypt(byte[], OutputStream)} and similar
     * @throws IOException
     */
    private byte[] retrieveExternalSharesCipherTextExpirationType2(
            byte[] ctPart, Signature signatureVerify, PublicKey pk,
            ExternalKeyDistributionStorage ekds) throws IOException
    {
        byte[] dataEncryptionKey = null; // "final" symmetric encryption key

        ExpirationType2Utils.CiphertextPart ctPartObj = ExpirationType2Utils.parseCiphertextPart(ctPart);
        if (ctPartObj != null) {
            // get secret shares from the DHT
            byte[][] shares = ekds.getBulkData(ctPartObj.locations);

            if (shares != null) {
                for (int j = 0; j < shares.length; j++) {
                    byte[] shareBytes = shares[j];
                    if (shareBytes == null || shareBytes.length == 0) {
                        shares[j] = null;
                        continue;
                    }

                    // parse shares received from the DHT and verify them if possible
                    ByteArrayInputStream shareReader = new ByteArrayInputStream(shareBytes);
                    int type = shareReader.read();
                    if (type == 1) {
                        // Type == 1 layout: len(share) + share + len(signature(share)) + signature(share)

                        int lenShare = shareReader.read();
                        if (lenShare < 8) {
                            logger.error("#decrypt: Share "+j+" length too short or negative: " + lenShare);
                            continue;
                        }

                        byte[] share = new byte[lenShare];

                        if (shareReader.read(share) != lenShare) {
                            logger.error("#decrypt: Incomplete share "+j+" read");
                            continue;
                        }

                        int signatureLen = shareReader.read();
                        if (signatureLen < 20) {
                            logger.error("#decrypt: Signature "+j+" length too short or negative: " + signatureLen);
                            continue;
                        }

                        byte[] signature = new byte[signatureLen];

                        if (shareReader.read(signature) != signatureLen) {
                            logger.error("#decrypt: Incomplete signature "+j+" read");
                            continue;
                        }

                        if (pk == null || signatureVerify == null) {
                            logger.warn("#decrypt: Can't verify the share "+j+", because a verifying key is not available");
                            shares[j] = share; // set the share correctly for the later stage
                            continue;
                        }

                        boolean validSignature = false;
                        try {
                            signatureVerify.initVerify(pk);
                            signatureVerify.update((byte)type);

                            // see that the index is `j+1` by looking into com.tiemens.secretshare.engine.SecretShare#split(BigInteger, Random)
                            signatureVerify.update(ByteBuffer.allocate(4).putInt(j + 1).array());
                            signatureVerify.update(share);
                            validSignature = signatureVerify.verify(signature);
                        } catch (Exception e) {
                            logger.info("#decrypt: Verifying signature "+j+" failed", e);
                        }

                        if (validSignature) {
                            shares[j] = share;
                        } else {
                            logger.info("#decrypt: signature for share "+j+" was not valid");
                            logger.debug("#decrypt: signature " + Hex.encodeHexString(signature) + " for share " + Hex.encodeHexString(share));
                            shares[j] = null;
                        }
                    } else {
                        logger.error("#decrypt: Unknown share "+j+" layout: " + type);
                        shares[j] = null;
                    }
                }

                // combine shares and XOR with the key from the ciphertext to get the data key
                try {
                    dataEncryptionKey = ExpirationType2Utils.xor(
                            ctPartObj.key3,
                            ExpirationType2Utils.combineShares(
                                    ExpirationType2Utils.prepareSharesFromArray(shares),
                                    ctPart
                            )
                    );
                } catch (SecretShareException e) {
                    logger.debug("#dec: Secret shares incomplete", e);
                }
            } else {
                logger.error("#dec: couldn't recover necessary shares");
            }
        } else {
            logger.error("#dec: Couldn't parse TYPE2 ctPart");
        }

        return dataEncryptionKey;
    }

    public void run(){
        decrypt();
    }
}
