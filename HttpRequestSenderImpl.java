package com.test.client.processor;

import com.test.security.SSLContextAlgorithms;
import com.test.security.SSLX509CertificateManager;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.ServiceUnavailableRetryStrategy;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultServiceUnavailableRetryStrategy;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.HTTP;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.util.StringUtils;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

/**
 * Created by on 2015/10/29.
 */
public class HttpRequestSenderImpl implements HttpRequestSender {
    public static final String HTTP_SCHEME = "http";
    public static final String HTTPS_SCHEME = "https";
    public static final String TRIGGER_PATH = "/oss/integration/rest/adaptation/trigger";
    public static final String QUERY_PATH = "/oss/integration/rest/adaptation/status";
    public static final int DEFAULT_HTTP_PORT = 80;
    public static final String APPLICATION_JSON = "application/json";
    public static final String ACCEPT = "Accept";
    public static final String DUMMY_PASSWORD = "xxxxxx";
    public static final int DEFAULT_MAX_RETRIES = 10;
    public static final int DEFAULT_RETRY_INTERVAL = 2;
    public static final int HTTP_RETURN_CODE_SUCCESS = 200;
    public static final int DEFAULT_SSL_PORT = 443;


    private Logger logger = LogManager.getLogger(HttpRequestSenderImpl.class);

    private int maxRetries;
    private int retryInterval;
    private int port;
    private String defaultUser;
    private boolean isSSL;

    public boolean isSSL() {
        return isSSL;
    }

    public void setIsSSL(boolean isSSL) {
        this.isSSL = isSSL;
    }

    public int getPort() {
        return port == 0 ? DEFAULT_HTTP_PORT : port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String getDefaultUser() {
        return defaultUser;
    }

    public void setDefaultUser(String defaultUser) {
        this.defaultUser = defaultUser;
    }

    public int getMaxRetries() {
        return maxRetries;
    }

    public void setMaxRetries(int maxRetries) {
        this.maxRetries = maxRetries;
    }

    public int getRetryInterval() {
        return retryInterval;
    }

    public void setRetryInterval(int retryInterval) {
        this.retryInterval = retryInterval;
    }

    @Override
    public String sendRequest(String ipAddress, RequestType requestType, Map<String, String> requestParams) throws IOException, URISyntaxException {

        return sendRequest(ipAddress, requestType, false, -1, requestParams);
    }

    @Override
    public String sendRequest(String ipAddress, RequestType requestType, Boolean retry, int timeout, Map<String, String> requestParams) throws IOException, URISyntaxException {

        String result = "";
        String scheme = isSSL() ? HTTPS_SCHEME : HTTP_SCHEME;

        switch (requestType) {
            case TRRIGER:
                result = constructRequestAndSend(ipAddress, requestParams, retry, scheme, TRIGGER_PATH);

                break;
            case QUERY:
                result = constructRequestAndSend(ipAddress, requestParams, retry, scheme, QUERY_PATH);
                break;
            default:
                break;

        }
        return result;
    }

    private String constructRequestAndSend(String ipAddress, Map<String, String> requestParams, Boolean retry, String scheme, String path) throws IOException, URISyntaxException {
        String result;
        HttpClient client = null;
        HttpClientBuilder httpClientBuilder = HttpClients.custom();
        final String user = StringUtils.isEmpty(Helper.getCurrentUser())?getDefaultUser():Helper.getCurrentUser();
        final String password = Helper.getPassword(user);

        URIBuilder uriBuilder = getUriBuilder(ipAddress, scheme, path, user, password);
        String jsonString = getPostEntity(requestParams, uriBuilder, path.contains(TRIGGER_PATH));


        if (isSSL()) {
            try {
                if(uriBuilder.getPort()== DEFAULT_HTTP_PORT){
                    uriBuilder.setPort(DEFAULT_SSL_PORT);
                }
                SSLContext sslContext = SSLX509CertificateManager.createTrustCASocketContext(uriBuilder.getHost(),uriBuilder.getPort(), SSLContextAlgorithms.TLS);
                httpClientBuilder = httpClientBuilder.setSSLContext(sslContext).setSSLHostnameVerifier(SSLConnectionSocketFactory.getDefaultHostnameVerifier());
            } catch (Exception e) {
                throw new IOException("Can't establish connection to " + ipAddress+":"+port + "due to:" + e.getMessage(), e);
            }
        }
        URI uri = uriBuilder.build();
        if (retry) {
            logger.debug("Retry has been chosen, maxRetries:" + getMaxRetries() + ",retryInterval:" + getRetryInterval());
            ServiceUnavailableRetryStrategy strategy = new DefaultServiceUnavailableRetryStrategy
                    (DEFAULT_MAX_RETRIES, DEFAULT_RETRY_INTERVAL);
            httpClientBuilder = httpClientBuilder.setServiceUnavailableRetryStrategy(strategy);
        }
        client = httpClientBuilder.build();


        HttpResponse response = null;
        if (path.contains(TRIGGER_PATH)) {
            HttpPost post = new HttpPost(uri);
            post.setEntity(new StringEntity(jsonString));
            post.setHeader(ACCEPT, APPLICATION_JSON);
            post.setHeader(HTTP.CONTENT_TYPE, "application/json");
            logger.debug("POST URI:" + post.getURI().toString().replace(password, DUMMY_PASSWORD));
            response = client.execute(post);
        } else {
            HttpGet get = new HttpGet(uri);
            get.setHeader(ACCEPT, APPLICATION_JSON);
            logger.debug("GET URI:" + get.getURI().toString().replace(password, DUMMY_PASSWORD));
            response = client.execute(get);
        }
        HttpEntity entity = response.getEntity();
        result = EntityUtils.toString(entity);
        if (response.getStatusLine().getStatusCode() != HTTP_RETURN_CODE_SUCCESS) {
            throw new HttpResponseException(response.getStatusLine().getStatusCode(), result);
        }
        logger.debug("EXECUTION RESULT:" + result);
        return result;
    }

    private URIBuilder getUriBuilder(String ipAddress, String scheme, String path, final String user, final String password) throws IOException {
        URIBuilder uriBuilder = new URIBuilder().setScheme(scheme).setHost(ipAddress).setPort(getPort()).setPath(path);
        uriBuilder.setUserInfo(user,password);
        return uriBuilder;
    }

    private String getPostEntity(Map<String, String> requestParams, URIBuilder uriBuilder, boolean isPostRequest) {
        String jsonString = "{";
        for (String key : requestParams.keySet()) {
            jsonString = jsonString + "\"" + key + "\":" + "\"" + requestParams.get(key) + "\",";
            if (!isPostRequest) {
                uriBuilder.setParameter(key, requestParams.get(key));
            }
        }
        jsonString = jsonString.substring(0, jsonString.length() - 1) + "}";
        logger.debug("Sent parameters:" + jsonString);
        return jsonString;
    }


}
