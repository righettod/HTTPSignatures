package burp;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64URL;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.*;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.StringEntity;
import org.tomitribe.auth.signatures.*;
import org.tomitribe.auth.signatures.Algorithm;

import java.io.*;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.text.Format;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public class Signing {

    static boolean DEBUG = false;
    static Map<String, X509Certificate> KEYID_CACHE = new ConcurrentHashMap<>();
    static Map<String, PrivateKey> PRIVATEKEY_CACHE = new ConcurrentHashMap<>();
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    static ConfigSettings globalSettings;

    public Signing(final IBurpExtenderCallbacks incallbacks) {
        callbacks = incallbacks;
        helpers = callbacks.getHelpers();
        globalSettings = new ConfigSettings();
    }

    /**
     * This method checks whether this extension is enabled for the Burp Suite tool
     *
     * @param toolFlag The <code>IBurpExtenderCallbacks</code> tool to check if this extension is enabled in the settings
     * @return Returns true if the extension is enabled for this tool, false if not.
     * The extension is enabled by default for Repeater, Intruder, and Scanner.
     */
    public static boolean enabledForTool(int toolFlag) {
        if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) {
            if (Signing.callbacks.loadExtensionSetting("enableProxy") != null) {
                return Signing.callbacks.loadExtensionSetting("enableProxy").equals("true");
            } else {
                return false; // default value: disabled for the proxy tool
            }
        } else if (toolFlag == IBurpExtenderCallbacks.TOOL_SCANNER) {
            if (Signing.callbacks.loadExtensionSetting("enableScanner") != null) {
                return Signing.callbacks.loadExtensionSetting("enableScanner").equals("true");
            } else {
                return true; // default value: enabled for the scanner tool
            }
        } else if (toolFlag == IBurpExtenderCallbacks.TOOL_INTRUDER) {
            if (Signing.callbacks.loadExtensionSetting("enableIntruder") != null) {
                return Signing.callbacks.loadExtensionSetting("enableIntruder").equals("true");
            } else {
                return true; // default value: enabled for the intruder tool
            }
        } else if (toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER) {
            if (Signing.callbacks.loadExtensionSetting("enableRepeater") != null) {
                return Signing.callbacks.loadExtensionSetting("enableRepeater").equals("true");
            } else {
                return true; // default value: enabled for the repeater tool
            }
        } else {
            return false;
        }
    }

    /**
     * This method signs the request.
     *
     * @param messageInfo This parameter contains the request to sign.
     * @return The signed request.
     */
    public static byte[] signRequest(IHttpRequestResponse messageInfo) {

        HttpRequestBase request;
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        List<String> headers = requestInfo.getHeaders();
        String body = "";
        String keyId = globalSettings.getString("keyId");

        // e.g. String privateKeyFilename = "/home/${USER}/private-key.pem";
        String privateKeyFilename = globalSettings.getString("Private key file name and path");
        PrivateKey privateKey = loadPrivateKey(privateKeyFilename);
        RequestSigner signer = new RequestSigner(keyId, privateKey);

        String url = requestInfo.getUrl().toString();
        log("\n\n\n\n[NEW REQUEST]");
        log("Input URL: " + url);

        String query = requestInfo.getUrl().getQuery();
        // URL decode to avoid double URL encoding later
        if (query != null) {
            query = URLDecoder.decode(query, StandardCharsets.UTF_8);

            // get port, but do not include it if its 80 or 443
            String port_str = "";
            if (requestInfo.getUrl().getPort() != -1) {
                int port = requestInfo.getUrl().getPort();
                if (port != 80 && port != 443) {
                    port_str = ":" + port;
                }
            }

            url = requestInfo.getUrl().getProtocol() + "://" +
                    requestInfo.getUrl().getHost() +
                    port_str +
                    requestInfo.getUrl().getPath() + "?" +
                    query;

            log("Decoded URL: " + url);
        }

        // Make sure the query is properly URL encoded
        try {
            URL jurl = new URL(url);
            String nullFragment = null;

            // get port, but do not include it if its 80 or 443
            String port_str = "";
            if (jurl.getPort() != -1) {
                int port = jurl.getPort();
                if (port != 80 && port != 443) {
                    port_str = ":" + port;
                }
            }
            URI uri = new URI(jurl.getProtocol(), jurl.getHost() + port_str, jurl.getPath(), jurl.getQuery(), nullFragment);
            url = uri.toString();
        } catch (MalformedURLException e) {
            err("URL " + url + " is malformed");
        } catch (URISyntaxException e) {
            err("URI " + url + " is malformed");
        }

        log("Encoded URL: " + url);

        // Hack for OCI
        if (url.contains("oraclecloud.com/")) {
            url = url.replaceAll(":", "%3A");
        }
        // we need some additional URL encoding for specific characters
        url = url.replaceAll("https%3A//", "https://");
        url = url.replaceAll("http%3A//", "http://");
        url = url.replaceAll(",", "%2C");
        //url = url.replaceAll("@", "%40");
        //url = url.replaceAll("\"","%22"); // encode double quotes (") in query parameters

        log("Encoded URL2: " + url);

        if (requestInfo.getMethod().equals("POST")) {
            request = new HttpPost(url);
        } else if (requestInfo.getMethod().equals("PUT")) {
            request = new HttpPut(url);
        } else if (requestInfo.getMethod().equals("GET")) {
            request = new HttpGet(url);
        } else if (requestInfo.getMethod().equals("HEAD")) {
            request = new HttpHead(url);
        } else if (requestInfo.getMethod().equals("DELETE")) {
            request = new HttpDelete(url);
        } else {
            err("ERROR: Unknown Method: " + requestInfo.getMethod());
            request = new HttpGet(url);
        }

        // add HTTP request body for POST and PUT requests
        if (requestInfo.getMethod().equals("POST") || requestInfo.getMethod().equals("PUT")) {
            HttpEntity entity;
            byte[] requestByte = messageInfo.getRequest();
            byte[] bodyByte = Arrays.copyOfRange(requestByte, requestInfo.getBodyOffset(), requestByte.length);
            try {
                body = new String(bodyByte);
                entity = new StringEntity(body);
                log("<BODY>" + body + "</BODY>");
                if (requestInfo.getMethod().equals("POST")) {
                    ((HttpPost) request).setEntity(entity);
                } else {
                    ((HttpPut) request).setEntity(entity);
                }
            } catch (UnsupportedEncodingException | ClassCastException e) {
                err("ERROR creating HTTP POST/PUT request body.");
                e.printStackTrace();
            }
        }

        log("*** OLD HEADERS START ***");
        // 'headers' includes the URL (e.g. GET, POST, etc.) as the first element
        String headerZero = headers.get(0); // save the URL for later
        headers.remove(0); // remove the URL (first element)

        String header_name = globalSettings.getString("Header Name").toLowerCase();

        // add all HTTP request headers except 'x-date' and the configured 'Header Name' value
        for (String header : headers) {
            log(header);
            if (header.toLowerCase().startsWith(header_name)) { // e.g. signature, authorization
                continue; // skip the configured header containing the signature/key
            } else if (header.toLowerCase().startsWith("x-date")) {
                continue; // skip "x-date" header
            } else {
                String[] headerPair = header.split(":", 2);
                request.addHeader(headerPair[0].trim(), headerPair[1].trim());
            }
        }
        log("*** OLD HEADERS END ***");

        signer.signRequest(request, header_name);

        // copy the HTTP headers from the signed request to newHeader
        List<String> newHeaders = new ArrayList<>();
        org.apache.http.Header[] tmpheaders = request.getAllHeaders();
        log("*** NEW HEADERS START ***");
        newHeaders.add(headerZero);
        for (org.apache.http.Header header : tmpheaders) {
            newHeaders.add(header.getName() + ": " + header.getValue());
            log(header.getName() + ": " + header.getValue());
        }
        log("*** NEW HEADERS END ***");

        return helpers.buildHttpMessage(newHeaders, body.getBytes());
    }

    /**
     * Logging a message for debugging purposes to stdout. Only logs when DEBUG is set to true.
     *
     * @param message The message to be logged
     */
    static void log(String message) {
        if (DEBUG) {
            Format formatter = new SimpleDateFormat("HH:mm:ss");
            String s = formatter.format(new Date());
            String m = String.format("[%s] %s", s, message);
            callbacks.printOutput(m);
        }
    }

    static void logError(String message) {
        Format formatter = new SimpleDateFormat("HH:mm:ss");
        String s = formatter.format(new Date());
        String m = String.format("[%s] %s", s, message);
        callbacks.printError(m);
    }

    /**
     * Logging an error message for debugging purposes to stderr.
     *
     * @param message The message to be logged
     */
    public static void err(String message) {
        callbacks.printError(message);
    }

    /*
     * The code below is based on
     * https://docs.cloud.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm#Java
     */

    /**
     * Load a {@link PrivateKey} from a file.
     */
    private static PrivateKey loadPrivateKey(String privateKeyFilename) {
        PrivateKey key;
        String source;
        try {
            //Quick lookup on the cache
            //Uses a cache to prevent to perform IO for each request to sign and reduce local IO
            if (PRIVATEKEY_CACHE.containsKey(privateKeyFilename)) {
                key = PRIVATEKEY_CACHE.get(privateKeyFilename);
                source = "cache";
            } else {
                try (InputStream privateKeyStream = Files.newInputStream(Paths.get(privateKeyFilename))) {
                    key = PEM.readPrivateKey(privateKeyStream);
                    PRIVATEKEY_CACHE.put(privateKeyFilename, key);
                    source = "disk";
                }
            }
        } catch (InvalidKeySpecException e) {
            logError("[ERROR] Invalid format for private key: " + e.getMessage());
            //If the key cannot be loaded then remove any cache entry related to it
            PRIVATEKEY_CACHE.remove(privateKeyFilename);
            throw new RuntimeException("Invalid format for private key");
        } catch (IOException e) {
            logError("[ERROR] Failed to load private key: " + e.getMessage());
            //If the key cannot be loaded then remove any cache entry related to it
            PRIVATEKEY_CACHE.remove(privateKeyFilename);
            throw new RuntimeException("Failed to load private key");
        }
        String msg = String.format("Private key loaded from %s: Algorithm is '%s' / Format is '%s' / File is '%s'.", source, key.getAlgorithm(), key.getFormat(), privateKeyFilename);
        log(msg);
        return key;
    }

    private static boolean isKeyIdURL(String keyId) {
        String keyIdLowerCase = keyId.toLowerCase(Locale.ROOT);
        return (keyIdLowerCase.startsWith("https://") || keyIdLowerCase.startsWith("http://"));
    }

    private static X509Certificate loadKeyId(String keyId) {
        X509Certificate cert;
        String source;
        try {
            //Quick lookup on the cache
            //Uses a cache to prevent to perform an HTTP request for each request to sign and reduce local IO
            if (KEYID_CACHE.containsKey(keyId)) {
                cert = KEYID_CACHE.get(keyId);
                source = "cache";
            } else {
                InputStream is;
                if (!isKeyIdURL(keyId)) {
                    is = new ByteArrayInputStream(Files.readAllBytes(Paths.get(keyId)));
                    source = "disk";
                } else {
                    try (HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()) {
                        HttpRequest request = HttpRequest.newBuilder()
                                .uri(new URI(keyId))
                                .header("X-Origin", "BurpExtension-HTTPSignatures-loadKeyId()")
                                .timeout(Duration.of(10, ChronoUnit.SECONDS))
                                .GET()
                                .build();
                        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                        is = new ByteArrayInputStream(response.body().getBytes(StandardCharsets.UTF_8));
                    }
                    source = "network";
                }
                cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
                KEYID_CACHE.put(keyId, cert);
            }
        } catch (Exception e) {
            logError("[ERROR] Failed to load keyId: " + e.getMessage());
            //If the certificate cannot be loaded then remove any cache entry related to it
            KEYID_CACHE.remove(keyId);
            throw new RuntimeException("Failed to load keyId");
        }
        String msg = String.format("Certificate loaded from %s: CN is '%s' / Location is '%s'.", source, cert.getSubjectX500Principal().getName(), keyId);
        log(msg);
        return cert;
    }

    /**
     * A light wrapper around https://github.com/tomitribe/http-signatures-java
     */
    public static class RequestSigner {
        private static final SimpleDateFormat DATE_FORMAT;
        //private static final String SIGNATURE_ALGORITHM = ConfigSettings.SIGNATURE_ALGORITHM.trim();
        private Map<String, List<String>> REQUIRED_HEADERS;

        static {
            DATE_FORMAT = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US);
            DATE_FORMAT.setTimeZone(TimeZone.getTimeZone("GMT"));
        }

        private final Map<String, Signer> signers;

        /**
         * @param apiKey     The identifier for a key uploaded through the console.
         * @param privateKey The private key that matches the uploaded public key for the given apiKey.
         */
        public RequestSigner(String apiKey, Key privateKey) {
            REQUIRED_HEADERS = new HashMap<String, List<String>>();
            REQUIRED_HEADERS.put("get", stringToList(globalSettings.getString("Header Names to Sign: GET").toLowerCase()));
            REQUIRED_HEADERS.put("head", stringToList(globalSettings.getString("Header Names to Sign: HEAD").toLowerCase()));
            REQUIRED_HEADERS.put("delete", stringToList(globalSettings.getString("Header Names to Sign: DELETE").toLowerCase()));
            REQUIRED_HEADERS.put("put", stringToList(globalSettings.getString("Header Names to Sign: PUT").toLowerCase()));
            REQUIRED_HEADERS.put("post", stringToList(globalSettings.getString("Header Names to Sign: POST").toLowerCase()));

            if (!ConfigSettings.SIGNATURE_MODE.equals(SignatureMode.JWS)) {
                this.signers = REQUIRED_HEADERS
                        .entrySet().stream()
                        .collect(Collectors.toMap(
                                entry -> entry.getKey(),
                                entry -> buildSigner(apiKey, privateKey, entry.getKey())));
            } else {
                log("RFC 9421 HTTP Signature signers init skipped due to JWS signature mode enabled.");
                this.signers = null;
            }
        }

        /**
         * Create a List from a string using the default StringTokenizer delimiter set (" \t\n\r\f")
         *
         * @param input_string The string to convert to a List
         * @return The converted string in a List format
         */
        private List stringToList(String input_string) {
            List<String> list = new ArrayList<String>();
            StringTokenizer st = new StringTokenizer(input_string);
            while (st.hasMoreTokens()) {
                list.add(st.nextToken());
            }
            return list;
        }

        /**
         * Create a {@link Signer} that expects the headers for a given method.
         *
         * @param apiKey     The identifier for a key uploaded through the console.
         * @param privateKey The private key that matches the uploaded public key for the given apiKey.
         * @param method     HTTP verb for this signer
         * @return Signer
         */
        protected Signer buildSigner(String apiKey, Key privateKey, String method) {
            Signature signature;
            if ("hs2019".equalsIgnoreCase(ConfigSettings.SIGNATURE_ALGORITHM.trim())) {
                AlgorithmParameterSpec spec = new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 32, 1);
                signature = new Signature(apiKey, SigningAlgorithm.HS2019, Algorithm.RSA_PSS, spec, null, REQUIRED_HEADERS.get(method.toLowerCase()));
            } else {
                signature = new Signature(apiKey, ConfigSettings.SIGNATURE_ALGORITHM.trim(), null, REQUIRED_HEADERS.get(method.toLowerCase()));
            }
            return new Signer(privateKey, signature);
        }

        /**
         * Sign a request, optionally including additional headers in the signature.
         *
         * <ol>
         * <li>If missing, insert the Date header (RFC 2822).</li>
         * <li>If PUT or POST, insert any missing content-type, content-length, x-content-sha256/digest</li>
         * <li>Verify that all headers to be signed are present.</li>
         * <li>Set the request's Authorization header to the computed signature.</li>
         * </ol>
         *
         * @param request     The request to sign
         * @param header_name The header name for the signature
         */
        public void signRequest(HttpRequestBase request, String header_name) {
            log("Sign requests.");
            final String method = request.getMethod().toLowerCase();
            // nothing to sign for options
            if (method.equals("options")) {
                log("Signing skipped because the request is an HTTP OPTIONS.");
                return;
            }

            boolean includeQuery = true;
            // Some implementations require query parameters in the Signatures, some don't.
            // If "Include query parameters in Signature" is set to "true", include query parameters in the Signature,
            // if set to "false" don't include query parameters in the Signature.
            if (globalSettings.getString("Include query parameters in Signature").equalsIgnoreCase("false")) {
                includeQuery = false;
            }
            final String path = extractPath(request.getURI(), includeQuery);

            // supply date if missing
            if (!request.containsHeader("date")) {
                request.addHeader("date", DATE_FORMAT.format(new Date()));
            }

            // supply host if missing
            if (!request.containsHeader("host")) {
                request.addHeader("host", request.getURI().getHost());
            }

            // supply content-type, content-length, and x-content-sha256/digest if missing (PUT and POST requests only)
            if (method.equals("put") || method.equals("post")) {
                if (!request.containsHeader("content-type")) {
                    request.addHeader("content-type", "application/json");
                }
                byte[] body = getRequestBody((HttpEntityEnclosingRequestBase) request);

                if (!request.containsHeader("content-length") ||
                        !request.containsHeader(globalSettings.getString("Digest Header Name").toLowerCase())) {

                    if (!request.containsHeader("content-length")) {
                        request.addHeader("content-length", Integer.toString(body.length));
                    }
                }

                // always recalculate the digest for POST/PUT requests
                if (globalSettings.getString("Digest Header Name").toLowerCase().equals("x-content-sha256")) {
                    request.setHeader("x-content-sha256", calculateSHA256(body));
                } else {
                    request.setHeader("digest", "SHA-256=" + calculateSHA256(body));
                }
            }

            //If request is GET/HEAD then add the digest of an empty string
            if (method.equalsIgnoreCase("get") || method.equalsIgnoreCase("head")) {
                log("Add the digest of an empty string.");
                byte[] body = "".getBytes(StandardCharsets.UTF_8);
                if (globalSettings.getString("Digest Header Name").toLowerCase().equals("x-content-sha256")) {
                    request.setHeader("x-content-sha256", calculateSHA256(body));
                } else {
                    request.setHeader("digest", "SHA-256=" + calculateSHA256(body));
                }
            }

            //Handle the case of the HTTP DELETE because such requests can have a body or not
            if (method.equalsIgnoreCase("delete")) {
                byte[] body = getRequestBody((HttpEntityEnclosingRequestBase) request);
                if (body.length == 0) {
                    log("Add the digest of an empty string.");
                    body = "".getBytes(StandardCharsets.UTF_8);
                }
                if (globalSettings.getString("Digest Header Name").toLowerCase().equals("x-content-sha256")) {
                    request.setHeader("x-content-sha256", calculateSHA256(body));
                } else {
                    request.setHeader("digest", "SHA-256=" + calculateSHA256(body));
                }
            }

            final Map<String, String> headers = extractHeadersToSign(request);
            String signature;
            if (ConfigSettings.SIGNATURE_MODE.equals(SignatureMode.JWS)) {
                if (request.getHeaders("digest").length == 0) {
                    String digest = request.getHeaders("x-content-sha256")[0].getValue();
                    log("According to the 'openFinance API Framework Implementation Guidelines' document: The request header name must be called 'Digest' so add it to fix the missing.");
                    request.setHeader("digest", digest);
                }
                signature = this.calculateJWSSignature(method, path, headers);
            } else {
                signature = this.calculateSignature(method, path, headers);
            }
            log("Generated signature for signature mode '" + ConfigSettings.SIGNATURE_MODE + "':\n" + signature);

            if (header_name.equalsIgnoreCase("Signature") && signature.startsWith("Signature ")) {
                // remove "Signature" from the beginning of the string as we use "Signature" as the header name
                signature = signature.substring(10);
            }
            request.setHeader(header_name, signature);
        }

        /**
         * Extract path and query string to build the (request-target) pseudo-header.
         * For the URI "http://www.host.com/somePath?foo=bar" return "/somePath?foo=bar"
         *
         * @param uri          The URI to extract the path
         * @param includeQuery If true include the query parameters (e.g. "?foo=bar"), if false do not include query params
         */
        private static String extractPath(URI uri, boolean includeQuery) {
            String path = uri.getRawPath();
            String query = uri.getRawQuery();
            if (query != null && !query.trim().isEmpty() && includeQuery) {
                path = path + "?" + query;
            }
            return path;
        }

        /**
         * Extract the headers required for signing from a {@link HttpRequestBase}, into a Map
         * that can be passed to {@link RequestSigner#calculateSignature}.
         *
         * <p>
         * Throws if a required header is missing, or if there are multiple values for a single header.
         * </p>
         *
         * @param request The request to extract headers from.
         */
        private Map<String, String> extractHeadersToSign(HttpRequestBase request) {
            List<String> headersToSign = REQUIRED_HEADERS.get(request.getMethod().toLowerCase());
            if (headersToSign == null) {
                throw new RuntimeException("Don't know how to sign method " + request.getMethod());
            }
            return headersToSign.stream()
                    // (request-target) is a pseudo-header
                    .filter(header -> !header.toLowerCase().equals("(request-target)") && !header.toLowerCase().equals("(created)"))
                    .collect(Collectors.toMap(
                            header -> header,
                            header -> {
                                if (!request.containsHeader(header)) {
                                    logError(String.format("[ERROR] Expected one value for header '%s' ==> signature skipped!", header));
                                    throw new MissingRequiredHeaderException(header);
                                }
                                if (request.getHeaders(header).length > 1) {
                                    throw new RuntimeException(
                                            String.format("Expected one value for header %s", header));
                                }

                                // If the configuration setting "Include the port in Signature" is set to false, remove the port.
                                // Some implementations such as Nextcloud Social do not include the port in the signature
                                // calculation.
                                if (header.equalsIgnoreCase("host") &&
                                        (request.getFirstHeader(header).getValue().indexOf(':') > -1) &&
                                        globalSettings.getString("Include the port in Signature").equalsIgnoreCase("false")) {
                                    // remove the port after the hostname, e.g. localhost:8080 -> localhost
                                    return request.getFirstHeader(header).getValue().split(":")[0];
                                } else {
                                    return request.getFirstHeader(header).getValue();
                                }
                            }));
        }

        /**
         * Wrapper around {@link Signer # sign}, returns the {@link Signature} as a String.
         *
         * @param method  Request method (GET, POST, ...)
         * @param path    The path + query string for forming the (request-target) pseudo-header
         * @param headers Headers to include in the signature.
         */
        private String calculateSignature(String method, String path, Map<String, String> headers) {
            try {
                Signer signer = this.signers.get(method);
                if (signer == null) {
                    throw new RuntimeException("Don't know how to sign method " + method);
                }
                return signer.sign(method, path, headers).toString();
            } catch (IOException e) {
                throw new RuntimeException("Failed to generate signature", e);
            }
        }


        /**
         * Calculate the Base64-encoded string representing the SHA256 of a request body
         *
         * @param body The request body to hash
         * @return The Base64-encoded SHA256 hash (empty string if NoSuchAlgorithmException)
         */
        private String calculateSHA256(byte[] body) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(body);
                return Base64.getEncoder().encodeToString(hash);
            } catch (NoSuchAlgorithmException e) {
                err("Unable to create SHA256 (NoSuchAlgorithmException)");
                return "";
            }
        }

        /**
         * Helper to safely extract a request body.  Because an {@link HttpEntity} may not be repeatable,
         * this function ensures the entity is reset after reading.  Null entities are treated as an empty string.
         *
         * @param request A request with a (possibly null) {@link HttpEntity}
         */
        private byte[] getRequestBody(HttpEntityEnclosingRequestBase request) {
            HttpEntity entity = request.getEntity();
            // null body is equivalent to an empty string
            if (entity == null) {
                return "".getBytes(StandardCharsets.UTF_8);
            }
            // May need to replace the request entity after consuming
            boolean consumed = !entity.isRepeatable();
            ByteArrayOutputStream content = new ByteArrayOutputStream();
            try {
                entity.writeTo(content);
            } catch (IOException e) {
                throw new RuntimeException("Failed to copy request body", e);
            }
            // Replace the now-consumed body with a copy of the content stream
            byte[] body = content.toByteArray();
            if (consumed) {
                request.setEntity(new ByteArrayEntity(body));
            }
            return body;
        }

        /**
         * Compute the JWS signature following the instructions<br>
         * from the document "openFinance Framework - Implementation Guidelines - Protocol Functions and Security Measures".<br>
         * Version 2.1 from 31/07/2024.<br>
         * See the section 6 of the document for the details about the signature.<br>
         * <b>Note:</b>The implementation was made to be easy to read, understand, debug and modify based on usage context.
         *
         * @param method  Request method (GET, POST, ...)
         * @param path    The path + query string for forming the (request-target) pseudo-header
         * @param headers Headers to include in the signature.
         * @return The JWS signed object as string.
         * @see "https://www.berlin-group.org/openfinance-downloads"
         * @see "https://c2914bdb-1b7a-4d22-b792-c58ac5d6648e.usrfiles.com/ugd/c2914b_0bc6a7d6cd6641c5a4a430d09c50f2fd.pdf"
         * @see "https://medium.com/syntaxa-tech-blog/open-banking-message-signing-b4ab4f7f92d1"
         * @see "https://developer.revolut.com/docs/guides/build-banking-apps/tutorials/work-with-json-web-signatures"
         */
        private String calculateJWSSignature(String method, String path, Map<String, String> headers) {
            try {
                //Load crypto materials
                String privateKeyFilename = globalSettings.getString("Private key file name and path");
                PrivateKey privateKey = loadPrivateKey(privateKeyFilename);
                String certificateLocation = globalSettings.getString("keyId");
                Certificate certificate = loadKeyId(certificateLocation);
                byte[] certificateHash = Base64.getDecoder().decode(calculateSHA256(certificate.getEncoded()));
                //Format content
                String x5uOverrideURL = globalSettings.getString("Override JWS 'x5u' attribute with URL").trim();
                Map<String, Object> sigD = new HashMap<>();
                List<String> pars = headers.keySet().stream().map(String::toLowerCase).collect(Collectors.toList());
                sigD.put("pars", pars);
                sigD.put("mid", "http://uri.etsi.org/19182/HttpHeaders");
                String currentDateTimeUTC = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
                //Create the JWS token using the "customParam" directive, every time it is possible, to explicitly set elements defined into the spec
                //and have a full control over the header created
                JWSHeader.Builder builder = new JWSHeader.Builder(JWSAlgorithm.parse(ConfigSettings.SIGNATURE_ALGORITHM));
                builder.type(JOSEObjectType.JOSE)
                        .base64URLEncodePayload(false)
                        .x509CertChain(List.of(Base64URL.encode(certificate.getEncoded())))
                        .x509CertSHA256Thumbprint(Base64URL.encode(certificateHash))
                        .criticalParams(Set.of("b64", "sigT", "sigD"))
                        .customParam("sigT", currentDateTimeUTC)
                        .customParam("sigD", sigD)
                        .customParam("aud", String.format("%s %s", method.toUpperCase(Locale.ROOT), path));
                if (isKeyIdURL(certificateLocation)) {
                    builder.x509CertURL(new URI(certificateLocation));
                }
                if(!x5uOverrideURL.isBlank()){
                    log("JWS header 'x5u' attribute overridden with value '" + x5uOverrideURL + "'.");
                    builder.x509CertURL(new URI(x5uOverrideURL));
                }
                JWSHeader jwsHeader = builder.build();
                Payload jwsPayload = new Payload("");
                JWSObject jwsObject = new JWSObject(jwsHeader, jwsPayload);
                //Sign and return serialized JWS object
                JWSSigner jwsSigner = new RSASSASigner(privateKey);
                jwsObject.sign(jwsSigner);
                return jwsObject.serialize();
            } catch (Exception e) {
                throw new RuntimeException("Failed to generate signature", e);
            }
        }
    }
}
