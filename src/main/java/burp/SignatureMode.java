package burp;

public enum SignatureMode {
    HS2019("hs2019"), RSASHA256("rsa-sha256"), JWS("RS256");

    public final String algorithm;

    private SignatureMode(String algorithm) {
        this.algorithm = algorithm;
    }
}
