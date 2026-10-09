// ============================================================
//  Admin — extends User (Inheritance)
//  OOP Concepts: Inheritance, static fields, full access rights
// ============================================================
public class Admin extends User {

    // ── Static field: shared across ALL Admin instances ──
    private static int adminCount = 0;

    private String accessLevel; // "super" or "standard"

    public Admin(int userId, String username, String email,
                 String accessLevel, String dept) {
        super(userId, username, email, "admin", dept);  // Call parent constructor
        this.accessLevel = accessLevel;
        adminCount++;                                    // Increment static counter
    }

    // ── Override abstract methods (Polymorphism) ──
    @Override
    public void displayInfo() {
        System.out.println("╔══════════════════════════════╗");
        System.out.println("║         ADMIN PROFILE        ║");
        System.out.println("╠══════════════════════════════╣");
        System.out.println("║ ID         : " + userId);
        System.out.println("║ Username   : " + username);
        System.out.println("║ Email      : " + email);
        System.out.println("║ Department : " + department);
        System.out.println("║ Access     : " + accessLevel.toUpperCase());
        System.out.println("║ Active     : " + (isActive ? "YES" : "NO"));
        System.out.println("╚══════════════════════════════╝");
    }

    @Override
    public boolean canAccess(String resource) {
        return true; // Admin has full access to everything
    }

    @Override
    public String getRoleDescription() {
        return "System Administrator — Full access to all modules, user management, and audit logs.";
    }

    // ── Static method: how many admins exist? ──
    public static int getAdminCount() { return adminCount; }

    // Getter
    public String getAccessLevel() { return accessLevel; }
}
