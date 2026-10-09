// ============================================================
//  ThreatActor — Entity class
//  OOP Concepts: Encapsulation, List of associated indicators
//                (demonstrates polymorphic collection)
// ============================================================
import java.util.ArrayList;
import java.util.List;

public class ThreatActor implements Comparable<ThreatActor> {

    private int    actorId;
    private String name;
    private String type;             // APT, Cybercriminal, Hacktivist, Insider, Nation-State
    private String originCountry;
    private String motivation;
    private int    sophistication;   // 1–10
    private String aliases;
    private String description;
    private boolean active;

    // Polymorphic collection — can hold IP, Domain, URL, or Hash indicators
    private List<Indicator> indicators;

    public ThreatActor(String name, String type, String country,
                       String motivation, int sophistication) {
        this.name           = name;
        this.type           = type;
        this.originCountry  = country;
        this.motivation     = motivation;
        this.sophistication = sophistication;
        this.active         = true;
        this.indicators     = new ArrayList<>();
    }

    // ── Add any Indicator subtype (Polymorphism in action) ──
    public void addIndicator(Indicator ind) {
        indicators.add(ind);
    }

    // ── Display all indicators — calls overridden display() on each ──
    public void displayIndicators() {
        if (indicators.isEmpty()) {
            System.out.println("  No indicators linked to this actor.");
            return;
        }
        System.out.println("  Linked Indicators (" + indicators.size() + "):");
        for (Indicator ind : indicators) {
            System.out.println("    " + ind);   // calls overridden toString()
        }
    }

    public void display() {
        System.out.println("=" .repeat(60));
        System.out.println("  THREAT ACTOR: " + name);
        System.out.println("  Type         : " + type);
        System.out.println("  Country      : " + (originCountry.isEmpty() ? "Unknown" : originCountry));
        System.out.println("  Motivation   : " + motivation);
        System.out.println("  Sophistication: " + sophistication + "/10");
        if (aliases != null && !aliases.isEmpty())
            System.out.println("  Aliases      : " + aliases);
        System.out.println("  Description  : " + description);
        System.out.println("  Active       : " + (active ? "YES" : "NO"));
        System.out.println("=".repeat(60));
    }

    // ── Comparable: sort by sophistication (highest first) ──
    @Override
    public int compareTo(ThreatActor other) {
        return Integer.compare(other.sophistication, this.sophistication);
    }

    // Getters / Setters
    public int    getActorId()       { return actorId; }
    public String getName()          { return name; }
    public String getType()          { return type; }
    public String getCountry()       { return originCountry; }
    public String getMotivation()    { return motivation; }
    public int    getSophistication(){ return sophistication; }
    public String getDescription()   { return description; }
    public boolean isActive()        { return active; }
    public int    getIndicatorCount(){ return indicators.size(); }

    public void setActorId(int id)            { this.actorId = id; }
    public void setDescription(String d)      { this.description = d; }
    public void setAliases(String a)          { this.aliases = a; }
    public void setActive(boolean a)          { this.active = a; }

    @Override
    public String toString() {
        return String.format("[%s] %s | Country: %s | Sophistication: %d/10",
                type, name, originCountry, sophistication);
    }
}
