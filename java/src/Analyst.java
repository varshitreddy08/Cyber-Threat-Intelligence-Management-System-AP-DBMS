// ============================================================
//  Analyst — extends User (Inheritance)
//  OOP Concepts: Inheritance, List of assigned work, restricted access
// ============================================================
import java.util.ArrayList;
import java.util.List;

public class Analyst extends User {

    private List<Integer> assignedIncidentIds;

    public Analyst(int userId, String username, String email, String dept) {
        super(userId, username, email, "analyst", dept);
        this.assignedIncidentIds = new ArrayList<>();
    }

    @Override
    public void displayInfo() {
        System.out.println("╔══════════════════════════════╗");
        System.out.println("║       ANALYST PROFILE        ║");
        System.out.println("╠══════════════════════════════╣");
        System.out.println("║ ID         : " + userId);
        System.out.println("║ Username   : " + username);
        System.out.println("║ Email      : " + email);
        System.out.println("║ Department : " + department);
        System.out.println("║ Workload   : " + assignedIncidentIds.size() + " incidents");
        System.out.println("╚══════════════════════════════╝");
    }

    @Override
    public boolean canAccess(String resource) {
        // Analysts cannot access admin-only sections
        return !resource.equalsIgnoreCase("user_management")
            && !resource.equalsIgnoreCase("audit_log_full");
    }

    @Override
    public String getRoleDescription() {
        return "Security Analyst — Can manage indicators, incidents, and generate reports.";
    }

    public void assignIncident(int incidentId) { assignedIncidentIds.add(incidentId); }
    public int  getWorkload()                  { return assignedIncidentIds.size(); }
    public List<Integer> getAssignedIncidents() { return assignedIncidentIds; }
}
