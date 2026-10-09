// ============================================================
//  URLIndicator — extends Indicator (Inheritance + Polymorphism)
// ============================================================
public class URLIndicator extends Indicator {

    private String  protocol;
    private String  host;
    private String  path;
    private boolean hasRedirect;

    public URLIndicator(String url, String severity, boolean malicious,
                        int confidence, boolean hasRedirect) {
        super(url, severity, malicious, confidence);
        this.hasRedirect = hasRedirect;
        parseURL(url);
    }

    private void parseURL(String url) {
        try {
            if (url.startsWith("https://")) {
                protocol = "HTTPS";
                String rest = url.substring(8);
                int slash = rest.indexOf('/');
                host = slash >= 0 ? rest.substring(0, slash) : rest;
                path = slash >= 0 ? rest.substring(slash) : "/";
            } else if (url.startsWith("http://")) {
                protocol = "HTTP";
                String rest = url.substring(7);
                int slash = rest.indexOf('/');
                host = slash >= 0 ? rest.substring(0, slash) : rest;
                path = slash >= 0 ? rest.substring(slash) : "/";
            } else if (url.startsWith("ftp://")) {
                protocol = "FTP";
                host = url.substring(6);
                path = "";
            } else {
                protocol = "UNKNOWN";
                host = url;
                path = "";
            }
        } catch (Exception e) {
            protocol = "UNKNOWN"; host = url; path = "";
        }
    }

    @Override
    public String getType() { return "URL"; }

    @Override
    public double analyze() {
        double score = switch (severity) {
            case "Critical" -> 5.0;
            case "High"     -> 4.0;
            case "Medium"   -> 3.0;
            default         -> 1.5;
        };
        score += (confidenceScore / 100.0) * 3.0;
        if (hasRedirect)           score += 0.5;  // Redirects are more suspicious
        if ("HTTP".equals(protocol)) score += 0.5; // Plain HTTP is less secure
        if ("FTP".equals(protocol))  score += 0.3;
        return Math.min(score, 10.0);
    }

    @Override
    public String getDescription() {
        return String.format("URL: %s | Protocol: %s | Host: %s | Redirect: %s",
                value, protocol, host, hasRedirect ? "YES" : "NO");
    }

    @Override
    public void display() {
        printLine(60);
        System.out.println("  TYPE        : URL");
        System.out.println("  VALUE       : " + value);
        System.out.println("  PROTOCOL    : " + protocol);
        System.out.println("  HOST        : " + host);
        System.out.println("  PATH        : " + path);
        System.out.println("  HAS REDIRECT: " + (hasRedirect ? "YES" : "NO"));
        System.out.println("  SEVERITY    : " + getSeverityLabel());
        System.out.println("  CONFIDENCE  : " + confidenceScore + "%");
        System.out.println("  MALICIOUS   : " + (isMalicious ? "YES" : "NO"));
        System.out.printf ("  RISK SCORE  : %.2f / 10.0%n", analyze());
        if (!context.isEmpty()) System.out.println("  CONTEXT     : " + context);
        printLine(60);
    }

    public String  getProtocol()   { return protocol; }
    public String  getHost()       { return host; }
    public boolean hasRedirect()   { return hasRedirect; }
}
