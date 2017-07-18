/*
* Copyright (c) 2016 All rights reserved.
*/
package com.test.security;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author 
 * @date 2016/10/17
 */
public class SSLX509CertificateManager {
    private static final Logger logger = LogManager.getLogger(SSLX509CertificateManager.class);
    private static final char[] HEXDIGITS = "0123456789abcdef".toCharArray();
    private static Pattern cnPattern = Pattern.compile("(?i)(cn=)([^,]*)");
    private static Map<KeyStoreOptions, KeyStore> stores = new HashMap<KeyStoreOptions, KeyStore>();


    private static String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 3);
        for (int b : bytes) {
            b &= 0xff;
            sb.append(HEXDIGITS[b >> 4]);
            sb.append(HEXDIGITS[b & 15]);
            sb.append(' ');
        }
        return sb.toString();
    }


    /**
     * start Hands hake for certs
     *
     * @param socket
     * @return
     */
    public static boolean startHandshake(SSLSocket socket) {
        try {
            logger.info("-Start shaking, check server certificates-");
            socket.startHandshake();
            System.out.println();
            logger.info("-Shaking and check server certificates completed-");
        } catch (IOException e) {
            logger.error(e.getMessage(), e);
            return false;
        }
        return true;
    }

    public static SSLContext createTrustCASocketContext(String host, int port, SSLContextAlgorithms algorithms) throws Exception {
        ConnectionConfiguration connConfig = new ConnectionConfiguration();
        connConfig.setServer(host);
        connConfig.setPort(port);
        KeyStore keyStore = SSLX509CertificateManager.getKeyStore(connConfig);
        if (keyStore.getCertificate(host + ":" + port) == null) {
            createTrustCASocket(host, port);
        }

        if (algorithms == null) {
            algorithms = SSLContextAlgorithms.TLS;
        }

        SSLContext sslContext = SSLContext.getInstance(algorithms.toString());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);
        X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
        SSLX509CertificateManager.CAX509TrustManager tm = new SSLX509CertificateManager.CAX509TrustManager(defaultTrustManager, keyStore, connConfig);
        sslContext.init(null, new TrustManager[]{tm}, new SecureRandom());
        return sslContext;
    }


    public static SSLSocket createTrustCASocket(String host, int port, ConnectionConfiguration config)
            throws Exception {
        if (config == null) {
            config = new ConnectionConfiguration();
        }
        KeyStore ks = getKeyStore(config);
        SSLContext context = SSLContext.getInstance("TLS");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
        CAX509TrustManager tm = new CAX509TrustManager(defaultTrustManager, ks, config);

        context.init(null, new TrustManager[]{tm}, new SecureRandom());
        SSLSocketFactory factory = context.getSocketFactory();

        logger.info("Connecting " + host + ":" + port + "...");
        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
        socket.setSoTimeout(10000);

        config.setServer(host);
        config.setPort(port);
        // config.setTrustKeyStore(ks);
        X509Certificate certificate = (X509Certificate) ks.getCertificate(host + ":" + port);

        if (certificate != null && isValid(certificate)) {
            logger.info("-Valid certificate, no handshake needed-");
            return socket;
        }
        if (!startHandshake(socket)) {
            logger.error("-Handshake failed-");
            return null;
        }
        X509Certificate[] chain = tm.chain;
        if (chain == null || chain.length == 0) {
            logger.error("-Certificate chain is null, authorization failed.-");
            return null;
        }

        if (config.isVerifyRootCAEnabled()) {
            boolean isValidRootCA = checkX509CertificateRootCA(ks, chain, config.isSelfSignedCertificateEnabled());
            if (!isValidRootCA) {
                return null;
            }
        }

        return socket;
    }

    /**
     * @param config
     * @return
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws FileNotFoundException
     */
    private static KeyStore getKeyStore(ConnectionConfiguration config) throws KeyStoreException, IOException,
            NoSuchAlgorithmException, CertificateException {
        KeyStore ks;
        synchronized (stores) {
            KeyStoreOptions options = new KeyStoreOptions(config.getTruststoreType(), config.getTruststorePath(),
                    config.getTruststorePassword());
            if (stores.containsKey(options)) {
                logger.info("Load trustKeystore from cache");
                ks = stores.get(options);

            } else {
                File file = new File(config.getTruststorePath());
                char[] password = config.getTruststorePassword().toCharArray();

                logger.info("Loading " + file + " certificates...");
                ks = KeyStore.getInstance(KeyStore.getDefaultType());
                if (!file.exists()) {
                    logger.warn("cert not existing , will create it...");
                    ks.load(null, password);
                } else {
                    logger.info("Loading existing certificate...");
                    InputStream in = new FileInputStream(file);
                    ks.load(in, password);
                    in.close();
                }
                stores.put(options, ks);
            }

        }
        return ks;
    }

    public static SSLSocket createTrustCASocket(String host, int port) throws Exception {

        return createTrustCASocket(host, port, null);
    }

    public static boolean isValid(X509Certificate cert) {
        if (cert == null) {
            return false;
        }
        try {
            cert.checkValidity();
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            logger.warn(e.getMessage(), e);
            return false;
        }
        return true;
    }

    /**
     * @param chain
     * @param config
     * @return
     */
    private static boolean checkX509CertificateValid(X509Certificate[] chain, ConnectionConfiguration config) {
        boolean result = true;
        if (config.isExpiredCertificatesCheckEnabled()) {
            result = result && checkX509CertificateExpired(chain);
        }

        if (config.isVerifyChainEnabled()) {
            result = result && checkX509CertificateChain(chain);
        }

        if (config.isNotMatchingDomainCheckEnabled()) {
            result = result && checkIsMatchDomain(chain, config.getServer());
        }

        return result;

    }

    /**
     * @param x509Certificates
     * @param server
     * @return
     */
    public static boolean checkIsMatchDomain(X509Certificate[] x509Certificates, String server) {
        server = server.toLowerCase();
        List<String> peerIdentities = getPeerIdentity(x509Certificates[0]);
        if (peerIdentities.size() == 1 && peerIdentities.get(0).startsWith("*.")) {
            String peerIdentity = peerIdentities.get(0).replace("*.", "");
            if (!server.endsWith(peerIdentity)) {
                return false;
            }
        } else {
            for (int i = 0; i < peerIdentities.size(); i++) {
                String peerIdentity = peerIdentities.get(i).replace("*.", "");
                if (server.endsWith(peerIdentity)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * @param trustStore
     * @param x509Certificates
     * @param isSelfSignedCertificate
     * @return
     */
    public static boolean checkX509CertificateRootCA(KeyStore trustStore, X509Certificate[] x509Certificates,
                                                     boolean isSelfSignedCertificate) {
        List<String> peerIdentities = getPeerIdentity(x509Certificates[0]);
        boolean trusted = false;
        try {
            int size = x509Certificates.length;
            trusted = trustStore.getCertificateAlias(x509Certificates[size - 1]) != null;
            if (!trusted && size == 1 && isSelfSignedCertificate) {
                logger.warn("-Trust self signed certificate by default.-");
                trusted = true;
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        if (!trusted) {
            logger.error("-Web site signed by root CA ：" + peerIdentities + " can't be trusted.");
        }

        return trusted;
    }

    /**
     * @param x509Certificates
     * @return
     */
    public static boolean checkX509CertificateExpired(X509Certificate[] x509Certificates) {
        Date date = new Date();
        for (int i = 0; i < x509Certificates.length; i++) {
            try {
                x509Certificates[i].checkValidity(date);
            } catch (GeneralSecurityException generalsecurityexception) {
                logger.error("certificate expired.");
                return false;
            }
        }
        return true;
    }

    /**
     * @param x509Certificates
     * @return
     */
    public static boolean checkX509CertificateChain(X509Certificate[] x509Certificates) {
        Principal principalLast = null;
        List<String> peerIdentities = getPeerIdentity(x509Certificates[0]);

        for (int i = x509Certificates.length - 1; i >= 0; i--) {
            X509Certificate x509certificate = x509Certificates[i];
            Principal principalIssuer = x509certificate.getIssuerDN();
            Principal principalSubject = x509certificate.getSubjectDN();
            if (principalLast != null) {
                if (principalIssuer.equals(principalLast)) {
                    try {
                        PublicKey publickey = x509Certificates[i + 1].getPublicKey();
                        x509Certificates[i].verify(publickey);
                    } catch (GeneralSecurityException generalsecurityexception) {

                        logger.error("invalid  certificate " + peerIdentities);
                        return false;
                    }
                } else {
                    logger.error("invalid  certificate" + peerIdentities);
                    return false;
                }
            }
            principalLast = principalSubject;
        }

        return true;
    }

    /**
     * @param certificate
     * @return
     * @see X509Certificate#getSubjectAlternativeNames()
     */
    private static List<String> getSubjectAlternativeNames(X509Certificate certificate) {
        List<String> identities = new ArrayList<String>();
        try {
            Collection<List<?>> altNames = certificate.getSubjectAlternativeNames();
            if (altNames == null) {
                return Collections.emptyList();
            }

            Iterator<List<?>> iterator = altNames.iterator();
            do {
                if (!iterator.hasNext())
                    break;
                List<?> altName = iterator.next();
                int size = altName.size();
                if (size >= 2) {
                    identities.add((String) altName.get(1));
                }

            } while (true);
        } catch (CertificateParsingException e) {
            e.printStackTrace();
        }
        return identities;
    }

    /**
     * @param x509Certificate
     * @return
     */
    public static List<String> getPeerIdentity(X509Certificate x509Certificate) {
        List<String> names = getSubjectAlternativeNames(x509Certificate);
        if (names.isEmpty()) {
            String name = x509Certificate.getSubjectDN().getName();
            Matcher matcher = cnPattern.matcher(name);
            if (matcher.find()) {
                name = matcher.group(2);
            }
            names = new ArrayList();
            names.add(name);
        }
        return names;
    }

    public static class CAX509TrustManager implements X509TrustManager {

        private final X509TrustManager tm;
        public MessageDigest sha1 = null;
        public MessageDigest md5 = null;
        private X509Certificate[] chain;
        private KeyStore keyStore;
        private ConnectionConfiguration config;

        public CAX509TrustManager(X509TrustManager tm, KeyStore ks, ConnectionConfiguration config)
                throws NoSuchAlgorithmException {
            this.tm = tm;
            this.keyStore = ks;
            sha1 = MessageDigest.getInstance("SHA1");
            md5 = MessageDigest.getInstance("MD5");
            this.config = config;
        }

        public X509Certificate[] getAcceptedIssuers() {
            return tm.getAcceptedIssuers();
        }

        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            tm.checkClientTrusted(chain, authType);
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            if (this.chain == null) {
                this.chain = getAcceptedIssuers();
            }
            if (chain != null && chain.length > 0) {
                if (!checkX509CertificateValid(chain, config)) {
                    logger.warn("Certificate verification failed.");
                    return;
                }
                for (int i = 0; i < chain.length; i++) {
                    X509Certificate certificate = chain[i];
                    if (i == 0) {
                        saveCAToKeyStore(certificate, config.getServer() + ":" + config.getPort());
                    } else {
                        saveCAToKeyStore(certificate, null);
                    }
                }
            }
        }

        public void saveCAToKeyStore(X509Certificate certificate, String aliasKey) throws CertificateEncodingException {
            try {
                X509Certificate cert = certificate;
                logger.debug("Subject[" + cert.getSubjectDN() + "]");
                logger.debug("Issuer[" + cert.getIssuerDN() + "]");
                sha1.update(cert.getEncoded());
                logger.debug("sha1[" + toHexString(sha1.digest()) + "]");
                md5.update(cert.getEncoded());
                logger.debug("md5[" + toHexString(md5.digest()) + "]");

                String alias = keyStore.getCertificateAlias(cert);
                if (alias == null || alias != null && !isValid(certificate)) {
                    if (aliasKey == null || aliasKey.length() == 0) {
                        alias = cert.getSubjectDN().getName();
                    } else {
                        alias = aliasKey;
                        logger.info("Setting certificate alias:" + alias);
                    }
                    keyStore.setCertificateEntry(alias, certificate);
                    OutputStream out = new FileOutputStream(config.getTruststorePath());
                    keyStore.store(out, config.getTruststorePassword().toCharArray());
                    out.close();
                    chain = Arrays.copyOf(chain, chain.length + 1);
                    chain[chain.length - 1] = certificate;
                    logger.debug(certificate.toString());
                }

            } catch (NoSuchAlgorithmException | CertificateException e) {
                logger.error(e.getMessage(), e);
                throw new CertificateEncodingException(e.getMessage(), e);
            } catch (IOException | KeyStoreException e) {
                logger.error(e.getMessage(), e);
                throw new CertificateEncodingException(e.getMessage(), e);
            }
        }

    }
}
