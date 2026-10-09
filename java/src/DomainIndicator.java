// ============================================================
//  DomainIndicator — extends Indicator (Inheritance + Polymorphism)
// ============================================================
public class DomainIndicator extends Indicator {

    private String  registrar;
    private boolean isDGA;          // Domain Generation Algorithm
    private int     domainAgeDays;

    public DomainIndicator(String domain, String severity, boolean malicious,
                           int confidence, String registrar, boolean isDGA, int ageDays) {
        super(domain, severity, malicious, confidence);
        this.registrar    = registrar;
        this.isDGA        = isDGA;
        this.domainAgeDays = ageDays;
    }

    @Override
    public String getType() { return "Domain"; }

    @Override
    public double analyze() {
        double score = switch (severity) {
            case "Critical" -> 5.0;
            case "High"     -> 4.0;
            case "Medium"   -> 3.0;
            default         -> 1.5;
        };
        score += (confidenceScore / 100.0) * 3.0;
        if (isDGA) score += 1.5;                       // DGA domains are extra suspicious
        if (domainAgeDays >= 0 && domainAgeDays < 30)  // Newly registered domain
            score += 0.5;
        return Math.min(score, 10.0);
    }

    @Override
    public String getDescription() {
        return String.format("Domain: %s | Registrar: %s | DGA: %s | Age: %d days",
                value, registrar.isEmpty() ? "Unknown" : registrar,
                isDGA ? "YES" : "NO", domainAgeDays);
    }

    @Override
    public void display() {
        printLine(60);
        System.out.println("  TYPE        : Domain");
        System.out.println("  VALUE       : " + value);
        System.out.println("  SEVERITY    : " + getSeverityLabel());
        System.out.println("  REGISTRAR   : " + (registrar.isEmpty() ? "Unknown" : registrar));
        System.out.println("  DGA FLAG    : " + (isDGA ? "YES - Algorithmically generated" : "NO"));
        System.out.println("  DOMAIN AGE  : " + (domainAgeDays >= 0 ? domainAgeDays + " days" : "Unknown"));
        System.out.println("  CONFIDENCE  : " + confidenceScore + "%");
        System.out.println("  MALICIOUS   : " + (isMalicious ? "YES" : "NO"));
        System.out.printf ("  RISK SCORE  : %.2f / 10.0%n", analyze());
        if (!context.isEmpty()) System.out.println("  CONTEXT     : " + context);
        printLine(60);
    }

    public boolean isDGA()         { return isDGA; }
    public String  getRegistrar()  { return registrar; }
    public int     getDomainAge()  { return domainAgeDays; }
}
