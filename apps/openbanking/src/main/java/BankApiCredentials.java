public class BankApiCredentials {
    private static String clientId = "5ae38ebaef7f2f0010f3f607";
    private static String publicKey = "e828a5368a3da958fc99c88af1695e";
    private static String environmentSecret = "";

    private static String devSecret = "a239e4436a3f7e8b25705b07d743f3";
    private static String sandboxSecret = "";
    private static boolean isSandbox = false;

    public BankApiCredentials(boolean sandbox) {
        if(sandbox) {
            environmentSecret = sandboxSecret;
            isSandbox = true;
        } else {
            environmentSecret = devSecret;
            isSandbox = false;
        }
    }

    public BankApiCredentials(String clientId, String publicKey, String environmentSecret, boolean isSandbox) {
        this.clientId = clientId;
        this.publicKey = publicKey;
        this.environmentSecret = environmentSecret;
        this.isSandbox = isSandbox;

    }

    public static boolean isSandbox() {
        return isSandbox;
    }

    public String clientId() {
        return this.clientId;
    }

    public String publicKey() {
        return this.publicKey;
    }

    public String environmentSecret() {
        return this.environmentSecret;
    }

}
