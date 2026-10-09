// ============================================================
//  User — Abstract Base Class
//  OOP Concepts: Abstraction, Encapsulation, Inheritance base
// ============================================================
public abstract class User {

    protected int     userId;
    protected String  username;
    protected String  email;
    protected String  role;
    protected String  department;
    protected boolean isActive;
    protected String  lastLogin;

    public User(int userId, String username, String email, String role, String dept) {
        this.userId     = userId;
        this.username   = username;
        this.email      = email;
        this.role       = role;
        this.department = dept;
        this.isActive   = true;
    }

    // ── Abstract methods — subclasses must implement ──
    public abstract void   displayInfo();
    public abstract boolean canAccess(String resource);
    public abstract String  getRoleDescription();

    // ── Common method (inherited by Admin, Analyst) ──
    public void login(String timestamp) {
        this.lastLogin = timestamp;
        System.out.println("[AUTH] User '" + username + "' logged in at " + timestamp);
    }

    // ── Getters ──
    public int    getUserId()     { return userId; }
    public String getUsername()   { return username; }
    public String getEmail()      { return email; }
    public String getRole()       { return role; }
    public String getDepartment() { return department; }
    public boolean isActive()     { return isActive; }
    public String  getLastLogin() { return lastLogin; }

    // ── Setters ──
    public void setActive(boolean a)    { this.isActive = a; }
    public void setLastLogin(String ts) { this.lastLogin = ts; }

    @Override
    public String toString() {
        return String.format("User[%s] %s (%s) — %s", role, username, email, department);
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof User)) return false;
        return this.userId == ((User)obj).userId;
    }
}
