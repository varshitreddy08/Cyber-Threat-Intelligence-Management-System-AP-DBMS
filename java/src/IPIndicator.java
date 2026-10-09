// ============================================================
//  IPIndicator — extends Indicator (Inheritance + Polymorphism)
//  Demonstrates: method overriding, IP-specific analysis
// ============================================================
public class IPIndicator extends Indicator {

    private String ipVersion;       // IPv4 or IPv6
    private String geolocation;
    private int    reputationScore; // 0=malicious, 100=clean

    public IPIndicator(String ip, String severity, boolean malicious,
                       int confidence, String ipVersion, String geo, int reputation) {
        super(ip, severity, malicious, confidence);  // Call parent constructor
        this.ipVersion      = ipVersion;
        this.geolocation    = geo;
        this.reputationScore = reputation;
    }

    // ── Override abstract methods (Polymorphism) ──
    @Override
    public String getType() { return "IP"; }

    @Override
    public double analyze() {
        double score = 0.0;
        // Severity contribution (0–5 points)
        score += switch (severity) {
            case "Critical" -> 5.0;
            case "High"     -> 4.0;
            case "Medium"   -> 3.0;
            default         -> 1.5;
        };
        // Confidence contribution (0–3 points)
        score += (confidenceScore / 100.0) * 3.0;
        // Reputation contribution: low reputation = higher risk
        score += ((100 - reputationScore) / 100.0) * 2.0;
        return Math.min(score, 10.0);
    }

    @Override
    public String getDescription() {
        return String.format("IP Address [%s] %s | Geo: %s | Reputation: %d/100",
                ipVersion, value, geolocation.isEmpty() ? "Unknown" : geolocation, reputationScore);
    }

    @Override
    public void display() {
        printLine(60);
        System.out.println("  TYPE        : IP Address");
        System.out.println("  VALUE       : " + value);
        System.out.println("  VERSION     : " + ipVersion);
        System.out.println("  SEVERITY    : " + getSeverityLabel());
        System.out.println("  GEOLOCATION : " + (geolocation.isEmpty() ? "Unknown" : geolocation));
        System.out.println("  REPUTATION  : " + reputationScore + "/100");
        System.out.println("  CONFIDENCE  : " + confidenceScore + "%");
        System.out.println("  MALICIOUS   : " + (isMalicious ? "YES" : "NO"));
        System.out.printf ("  RISK SCORE  : %.2f / 10.0%n", analyze());
        if (!context.isEmpty()) System.out.println("  CONTEXT     : " + context);
        printLine(60);
    }

    // ── IP-specific methods ──
    public boolean isPrivateAddress() {
        return value.startsWith("10.")
            || value.startsWith("192.168.")
            || value.startsWith("172.16.")
            || value.equals("127.0.0.1");
    }

    // Getters / Setters
    public String getIpVersion()       { return ipVersion; }
    public String getGeolocation()     { return geolocation; }
    public int    getReputationScore() { return reputationScore; }
    public void   setGeolocation(String g)  { this.geolocation = g; }
    public void   setReputation(int r)      { this.reputationScore = r; }
}
