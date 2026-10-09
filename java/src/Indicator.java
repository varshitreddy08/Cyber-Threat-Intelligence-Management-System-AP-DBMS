// ============================================================
//  Indicator — Abstract Base Class
//  OOP Concepts:
//    - Abstraction  : abstract class with abstract methods
//    - Encapsulation: private/protected fields + getters/setters
//    - Polymorphism : subclasses override analyze(), display()
// ============================================================
public abstract class Indicator implements Comparable<Indicator> {

    // ── Protected fields (accessible to subclasses) ──
    protected int    id;
    protected String value;
    protected String severity;       // Critical / High / Medium / Low
    protected String status;         // Active / Inactive / Archived
    protected boolean isMalicious;
    protected int    confidenceScore; // 0–100
    protected String tags;
    protected String context;
    protected int    actorId;
    protected int    reportedBy;
    protected String firstSeen;
    protected String lastSeen;

    // ── Constructor ──
    public Indicator(String value, String severity, boolean isMalicious, int confidence) {
        this.value           = value;
        this.severity        = severity;
        this.isMalicious     = isMalicious;
        this.confidenceScore = confidence;
        this.status          = "Active";
        this.tags            = "";
        this.context         = "";
    }

    // ── Abstract methods — must be implemented by each subclass ──
    public abstract String getType();           // "IP", "Domain", "URL", "Hash"
    public abstract double analyze();           // Returns risk score 0.0–10.0
    public abstract String getDescription();
    public abstract void   display();

    // ── Common non-abstract method (inherited by all) ──
    public String getSeverityLabel() {
        return switch (severity) {
            case "Critical" -> "[!!!] CRITICAL";
            case "High"     -> "[ !! ] HIGH";
            case "Medium"   -> "[  ! ] MEDIUM";
            default         -> "[    ] LOW";
        };
    }

    // ── Getters ──
    public int     getId()             { return id; }
    public String  getValue()          { return value; }
    public String  getSeverity()       { return severity; }
    public String  getStatus()         { return status; }
    public boolean isMalicious()       { return isMalicious; }
    public int     getConfidence()     { return confidenceScore; }
    public String  getTags()           { return tags; }
    public String  getContext()        { return context; }
    public int     getActorId()        { return actorId; }
    public int     getReportedBy()     { return reportedBy; }

    // ── Setters ──
    public void setId(int id)                         { this.id = id; }
    public void setSeverity(String s)                 { this.severity = s; }
    public void setStatus(String s)                   { this.status = s; }
    public void setMalicious(boolean m)               { this.isMalicious = m; }
    public void setConfidence(int c)                  { this.confidenceScore = c; }
    public void setTags(String t)                     { this.tags = t; }
    public void setContext(String c)                  { this.context = c; }
    public void setActorId(int id)                    { this.actorId = id; }
    public void setReportedBy(int id)                 { this.reportedBy = id; }
    public void setFirstSeen(String ts)               { this.firstSeen = ts; }
    public void setLastSeen(String ts)                { this.lastSeen = ts; }

    // ── Comparable: sort by confidence (highest first) ──
    @Override
    public int compareTo(Indicator other) {
        return Integer.compare(other.confidenceScore, this.confidenceScore);
    }

    // ── toString: useful for logging and display ──
    @Override
    public String toString() {
        return String.format("[%s] %s | Severity: %s | Confidence: %d%%",
                getType(), value, severity, confidenceScore);
    }

    // ── equals ──
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof Indicator)) return false;
        Indicator other = (Indicator) obj;
        return this.value.equals(other.value) && this.getType().equals(other.getType());
    }

    @Override
    public int hashCode() { return (getType() + value).hashCode(); }

    // ── Helper: print separator line ──
    protected void printLine(int width) {
        System.out.println("-".repeat(width));
    }
}
