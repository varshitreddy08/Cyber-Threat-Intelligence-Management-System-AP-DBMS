// ============================================================
//  CTIMS — Main Application Controller (Facade Pattern)
//  OOP Concepts: Facade, Singleton usage, Polymorphism,
//                Generic types, Exception handling, all combined
// ============================================================
import java.util.*;

public class CTIMS {

    private DatabaseManager db;
    private ThreatAnalyzer  analyzer;
    private User            currentUser;
    private Scanner         sc;

    // ── Constructor ──
    public CTIMS() {
        sc       = new Scanner(System.in);
        db       = DatabaseManager.getInstance();
        analyzer = new AdvancedAnalyzer();   // Default strategy
    }

    // ════════════════════════════════════════════
    //  AUTHENTICATION
    // ════════════════════════════════════════════
    public boolean login() {
        clearScreen();
        printBanner();
        System.out.print("\n  Username: ");
        String uname = sc.nextLine().trim();
        System.out.print("  Password: ");
        String pass  = sc.nextLine().trim();

        try {
            String sql = "SELECT user_id, username, email, role, department " +
                         "FROM ctims_users " +
                         "WHERE username = " + db.escape(uname) +
                         "  AND password_hash = " + db.escape(pass) +
                         "  AND is_active = TRUE";

            List<Map<String,String>> rows = db.executeQuery(sql);

            if (rows.isEmpty()) {
                System.out.println("\n  [DENIED] Invalid username or password.");
                return false;
            }

            Map<String,String> row = rows.get(0);
            int    uid  = Integer.parseInt(row.get("user_id"));
            String role = row.get("role");
            String dept = row.getOrDefault("department", "");

            currentUser = "admin".equals(role)
                ? new Admin(uid, row.get("username"), row.get("email"), "standard", dept)
                : new Analyst(uid, row.get("username"), row.get("email"), dept);

            currentUser.login(new java.util.Date().toString());

            // Update last_login in DB
            db.executeUpdate("UPDATE ctims_users SET last_login = CURRENT_TIMESTAMP " +
                             "WHERE user_id = " + uid);

            System.out.println("\n  [OK] Welcome, " + currentUser.getUsername() +
                               "! Role: " + role.toUpperCase());
            Thread.sleep(800);
            return true;

        } catch (Exception e) {
            System.out.println("  [ERROR] " + e.getMessage());
            return false;
        }
    }

    // ════════════════════════════════════════════
    //  MAIN MENU
    // ════════════════════════════════════════════
    public void run() {
        boolean running = true;
        while (running) {
            clearScreen();
            printBanner();
            System.out.println("\n  Logged in as: " + currentUser.getUsername() +
                               " [" + currentUser.getRole().toUpperCase() + "]");
            System.out.println("\n  ┌─────────────────────────────────┐");
            System.out.println("  │          MAIN MENU              │");
            System.out.println("  ├─────────────────────────────────┤");
            System.out.println("  │  1. Indicator Management (IOC)  │");
            System.out.println("  │  2. Threat Actor Management     │");
            System.out.println("  │  3. Malware Management          │");
            System.out.println("  │  4. Vulnerability Tracking      │");
            System.out.println("  │  5. Incident Management         │");
            System.out.println("  │  6. Reports & Analytics         │");
            System.out.println("  │  7. Audit Log                   │");
            System.out.println("  │  0. Logout & Exit               │");
            System.out.println("  └─────────────────────────────────┘");
            System.out.print("\n  Enter choice: ");

            switch (sc.nextLine().trim()) {
                case "1" -> menuIndicators();
                case "2" -> menuThreatActors();
                case "3" -> menuMalware();
                case "4" -> menuVulnerabilities();
                case "5" -> menuIncidents();
                case "6" -> menuReports();
                case "7" -> viewAuditLog();
                case "0" -> running = false;
                default  -> { System.out.println("  Invalid choice."); pause(); }
            }
        }
        System.out.println("\n  Goodbye! Stay Secure.\n");
        db.close();
    }

    // ════════════════════════════════════════════
    //  1. INDICATOR MANAGEMENT
    // ════════════════════════════════════════════
    private void menuIndicators() {
        boolean back = false;
        while (!back) {
            clearScreen();
            System.out.println("\n  ═══════ INDICATOR MANAGEMENT ═══════");
            System.out.println("  1. Add IP Indicator");
            System.out.println("  2. Add Domain Indicator");
            System.out.println("  3. Add URL Indicator");
            System.out.println("  4. Add Hash Indicator");
            System.out.println("  5. List All Indicators");
            System.out.println("  6. Search Indicators");
            System.out.println("  7. Update Indicator Status");
            System.out.println("  8. Delete Indicator");
            System.out.println("  9. Analyze Indicator (Risk Score)");
            System.out.println("  0. Back");
            System.out.print("\n  Choice: ");
            switch (sc.nextLine().trim()) {
                case "1" -> addIPIndicator();
                case "2" -> addDomainIndicator();
                case "3" -> addURLIndicator();
                case "4" -> addHashIndicator();
                case "5" -> listIndicators();
                case "6" -> searchIndicators();
                case "7" -> updateIndicatorStatus();
                case "8" -> deleteIndicator();
                case "9" -> analyzeIndicator();
                case "0" -> back = true;
            }
        }
    }

    private void addIPIndicator() {
        clearScreen();
        System.out.println("\n  ── Add IP Indicator ──");
        String ip         = prompt("  IP Address");
        String severity   = promptChoice("  Severity [Critical/High/Medium/Low]",
                                         "Critical","High","Medium","Low");
        String malicious  = promptChoice("  Is Malicious? [yes/no]", "yes","no");
        int    confidence = promptInt("  Confidence Score (0-100)", 0, 100);
        String ipVer      = promptChoice("  IP Version [IPv4/IPv6]", "IPv4","IPv6");
        String geo        = prompt("  Geolocation (e.g. Mumbai, India)");
        int    reputation = promptInt("  Reputation Score (0=bad, 100=clean)", 0, 100);
        String context    = prompt("  Context/Notes");
        int    actorId    = promptInt("  Threat Actor ID (0 if unknown)", 0, 9999);

        // Create Java OOP object (demonstrates Polymorphism)
        IPIndicator ind = new IPIndicator(ip, severity, "yes".equalsIgnoreCase(malicious),
                                          confidence, ipVer, geo, reputation);
        ind.setContext(context);
        ind.setActorId(actorId);
        ind.setReportedBy(currentUser.getUserId());

        System.out.println("\n  Indicator Object Created:");
        ind.display();
        System.out.printf("  Calculated Risk Score: %.2f%n", ind.analyze());

        System.out.print("\n  Save to database? [yes/no]: ");
        if (!"yes".equalsIgnoreCase(sc.nextLine().trim())) return;

        String actorRef = actorId > 0 ? String.valueOf(actorId) : "NULL";
        String sql = String.format(
            "INSERT INTO indicators (indicator_type, indicator_value, severity, status, " +
            "is_malicious, confidence_score, ip_version, geolocation, reputation_score, " +
            "context, actor_id, reported_by) VALUES " +
            "('IP', %s, %s, 'Active', %s, %d, %s, %s, %d, %s, %s, %d) RETURNING indicator_id",
            db.escape(ip), db.escape(severity),
            "yes".equalsIgnoreCase(malicious) ? "TRUE" : "FALSE",
            confidence, db.escape(ipVer), db.escape(geo), reputation,
            db.escape(context), actorRef, currentUser.getUserId()
        );

        int newId = db.executeInsertReturning(sql);
        System.out.println("\n  [OK] IP Indicator saved. ID = " + newId);
        System.out.println("  [NOTE] Trigger fired: audit_log entry created automatically.");
        if ("Critical".equals(severity) && "yes".equalsIgnoreCase(malicious))
            System.out.println("  [NOTE] Trigger fired: Auto-incident created for Critical IOC!");
        pause();
    }

    private void addDomainIndicator() {
        clearScreen();
        System.out.println("\n  ── Add Domain Indicator ──");
        String domain     = prompt("  Domain Name");
        String severity   = promptChoice("  Severity [Critical/High/Medium/Low]",
                                         "Critical","High","Medium","Low");
        String malicious  = promptChoice("  Is Malicious? [yes/no]", "yes","no");
        int    confidence = promptInt("  Confidence Score (0-100)", 0, 100);
        String registrar  = prompt("  Registrar (optional)");
        String isDGA      = promptChoice("  Is DGA (algorithmically generated)? [yes/no]", "yes","no");
        int    ageDays    = promptInt("  Domain Age in Days (-1 if unknown)", -1, 99999);
        String context    = prompt("  Context/Notes");
        int    actorId    = promptInt("  Threat Actor ID (0 if unknown)", 0, 9999);

        DomainIndicator ind = new DomainIndicator(domain, severity,
                "yes".equalsIgnoreCase(malicious), confidence,
                registrar, "yes".equalsIgnoreCase(isDGA), ageDays);
        ind.setContext(context);

        System.out.println("\n  Indicator Object Created:");
        ind.display();

        System.out.print("\n  Save to database? [yes/no]: ");
        if (!"yes".equalsIgnoreCase(sc.nextLine().trim())) return;

        String actorRef = actorId > 0 ? String.valueOf(actorId) : "NULL";
        String sql = String.format(
            "INSERT INTO indicators (indicator_type, indicator_value, severity, status, " +
            "is_malicious, confidence_score, registrar, is_dga, context, actor_id, reported_by) " +
            "VALUES ('Domain', %s, %s, 'Active', %s, %d, %s, %s, %s, %s, %d) RETURNING indicator_id",
            db.escape(domain), db.escape(severity),
            "yes".equalsIgnoreCase(malicious) ? "TRUE" : "FALSE",
            confidence, db.escape(registrar),
            "yes".equalsIgnoreCase(isDGA) ? "TRUE" : "FALSE",
            db.escape(context), actorRef, currentUser.getUserId()
        );
        int newId = db.executeInsertReturning(sql);
        System.out.println("\n  [OK] Domain Indicator saved. ID = " + newId);
        pause();
    }

    private void addURLIndicator() {
        clearScreen();
        System.out.println("\n  ── Add URL Indicator ──");
        String url        = prompt("  URL");
        String severity   = promptChoice("  Severity [Critical/High/Medium/Low]",
                                         "Critical","High","Medium","Low");
        String malicious  = promptChoice("  Is Malicious? [yes/no]", "yes","no");
        int    confidence = promptInt("  Confidence Score (0-100)", 0, 100);
        String redirect   = promptChoice("  Has Redirect? [yes/no]", "yes","no");
        String context    = prompt("  Context/Notes");
        int    actorId    = promptInt("  Threat Actor ID (0 if unknown)", 0, 9999);

        URLIndicator ind = new URLIndicator(url, severity,
                "yes".equalsIgnoreCase(malicious), confidence,
                "yes".equalsIgnoreCase(redirect));
        ind.setContext(context);

        System.out.println("\n  Indicator Object Created:");
        ind.display();

        System.out.print("\n  Save to database? [yes/no]: ");
        if (!"yes".equalsIgnoreCase(sc.nextLine().trim())) return;

        String actorRef = actorId > 0 ? String.valueOf(actorId) : "NULL";
        String sql = String.format(
            "INSERT INTO indicators (indicator_type, indicator_value, severity, status, " +
            "is_malicious, confidence_score, has_redirect, context, actor_id, reported_by) " +
            "VALUES ('URL', %s, %s, 'Active', %s, %d, %s, %s, %s, %d) RETURNING indicator_id",
            db.escape(url), db.escape(severity),
            "yes".equalsIgnoreCase(malicious) ? "TRUE" : "FALSE",
            confidence,
            "yes".equalsIgnoreCase(redirect) ? "TRUE" : "FALSE",
            db.escape(context), actorRef, currentUser.getUserId()
        );
        int newId = db.executeInsertReturning(sql);
        System.out.println("\n  [OK] URL Indicator saved. ID = " + newId);
        pause();
    }

    private void addHashIndicator() {
        clearScreen();
        System.out.println("\n  ── Add Hash Indicator ──");
        String hash       = prompt("  Hash Value");
        String severity   = promptChoice("  Severity [Critical/High/Medium/Low]",
                                         "Critical","High","Medium","Low");
        String malicious  = promptChoice("  Is Malicious? [yes/no]", "yes","no");
        int    confidence = promptInt("  Confidence Score (0-100)", 0, 100);
        String hashType   = promptChoice("  Hash Type [MD5/SHA1/SHA256/SHA512]",
                                         "MD5","SHA1","SHA256","SHA512");
        String fileName   = prompt("  File Name (optional)");
        long   fileSize   = promptLong("  File Size in Bytes (0 if unknown)");
        String context    = prompt("  Context/Notes");
        int    actorId    = promptInt("  Threat Actor ID (0 if unknown)", 0, 9999);

        HashIndicator ind = new HashIndicator(hash, severity,
                "yes".equalsIgnoreCase(malicious), confidence,
                hashType, fileName, fileSize);
        ind.setContext(context);

        if (!ind.validateLength())
            System.out.println("  [WARN] Hash length doesn't match expected " + hashType + " length.");

        System.out.println("\n  Indicator Object Created:");
        ind.display();

        System.out.print("\n  Save to database? [yes/no]: ");
        if (!"yes".equalsIgnoreCase(sc.nextLine().trim())) return;

        String actorRef = actorId > 0 ? String.valueOf(actorId) : "NULL";
        String fileSizeStr = fileSize > 0 ? String.valueOf(fileSize) : "NULL";
        String sql = String.format(
            "INSERT INTO indicators (indicator_type, indicator_value, severity, status, " +
            "is_malicious, confidence_score, hash_type, file_name, file_size_bytes, " +
            "context, actor_id, reported_by) " +
            "VALUES ('Hash', %s, %s, 'Active', %s, %d, %s, %s, %s, %s, %s, %d) RETURNING indicator_id",
            db.escape(hash), db.escape(severity),
            "yes".equalsIgnoreCase(malicious) ? "TRUE" : "FALSE",
            confidence, db.escape(hashType), db.escape(fileName), fileSizeStr,
            db.escape(context), actorRef, currentUser.getUserId()
        );
        int newId = db.executeInsertReturning(sql);
        System.out.println("\n  [OK] Hash Indicator saved. ID = " + newId);
        pause();
    }

    private void listIndicators() {
        clearScreen();
        System.out.println("\n  ═══ ALL INDICATORS ═══");
        System.out.println("  Filter by type:");
        System.out.println("  [1] All  [2] IP  [3] Domain  [4] URL  [5] Hash");
        System.out.print("  Choice: ");
        String choice = sc.nextLine().trim();
        String typeFilter = switch (choice) {
            case "2" -> " AND indicator_type = 'IP'";
            case "3" -> " AND indicator_type = 'Domain'";
            case "4" -> " AND indicator_type = 'URL'";
            case "5" -> " AND indicator_type = 'Hash'";
            default  -> "";
        };

        // Demonstrates: SELECT, WHERE, LEFT JOIN, CASE, ORDER BY
        String sql = "SELECT i.indicator_id, i.indicator_type, i.indicator_value, " +
                     "i.severity, i.status, i.confidence_score, i.is_malicious, " +
                     "COALESCE(ta.actor_name, 'Unknown') AS actor, " +
                     "CASE WHEN i.confidence_score >= 90 THEN 'Confirmed' " +
                     "     WHEN i.confidence_score >= 70 THEN 'Probable' " +
                     "     WHEN i.confidence_score >= 50 THEN 'Suspected' " +
                     "     ELSE 'Unknown' END AS confidence_label " +
                     "FROM indicators i " +
                     "LEFT JOIN threat_actors ta ON i.actor_id = ta.actor_id " +
                     "WHERE 1=1 " + typeFilter +
                     " ORDER BY CASE i.severity " +
                     "  WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 " +
                     "  WHEN 'Medium' THEN 3 ELSE 4 END";

        List<Map<String,String>> rows = db.executeQuery(sql);
        System.out.println();
        DatabaseManager.printTable(rows);
        pause();
    }

    private void searchIndicators() {
        clearScreen();
        System.out.println("\n  ═══ SEARCH INDICATORS ═══");
        System.out.println("  Search by:");
        System.out.println("  [1] Value (LIKE search)   [2] Severity   [3] Threat Actor");
        System.out.print("  Choice: ");
        String choice = sc.nextLine().trim();
        String sql = "";

        switch (choice) {
            case "1" -> {
                // Demonstrates LIKE operator
                String keyword = prompt("  Enter search term");
                sql = "SELECT indicator_id, indicator_type, indicator_value, severity, status " +
                      "FROM indicators WHERE indicator_value LIKE " +
                      db.escape("%" + keyword + "%") + " ORDER BY severity";
                System.out.println("\n  [SQL] Using LIKE operator: value LIKE '%" + keyword + "%'");
            }
            case "2" -> {
                // Demonstrates IN operator
                String sev = promptChoice("  Severity [Critical/High/Medium/Low]",
                                          "Critical","High","Medium","Low");
                sql = "SELECT indicator_id, indicator_type, indicator_value, " +
                      "severity, confidence_score FROM indicators " +
                      "WHERE severity = " + db.escape(sev) + " AND is_malicious = TRUE " +
                      "ORDER BY confidence_score DESC";
                System.out.println("\n  [SQL] Filter by severity = '" + sev + "'");
            }
            case "3" -> {
                // Demonstrates INNER JOIN + subquery
                String actorName = prompt("  Actor name (partial)");
                sql = "SELECT i.indicator_type, i.indicator_value, i.severity, ta.actor_name " +
                      "FROM indicators i INNER JOIN threat_actors ta ON i.actor_id = ta.actor_id " +
                      "WHERE ta.actor_name LIKE " + db.escape("%" + actorName + "%");
                System.out.println("\n  [SQL] Using INNER JOIN with threat_actors");
            }
            default -> { System.out.println("  Invalid."); pause(); return; }
        }

        List<Map<String,String>> rows = db.executeQuery(sql);
        DatabaseManager.printTable(rows);
        pause();
    }

    private void updateIndicatorStatus() {
        clearScreen();
        System.out.println("\n  ═══ UPDATE INDICATOR STATUS ═══");
        int id = promptInt("  Indicator ID", 1, 99999);
        String newStatus = promptChoice("  New Status [Active/Inactive/Archived]",
                                        "Active","Inactive","Archived");
        // Demonstrates UPDATE + trigger fires (auto audit log)
        String sql = "UPDATE indicators SET status = " + db.escape(newStatus) +
                     " WHERE indicator_id = " + id;
        int affected = db.executeUpdate(sql);
        if (affected > 0) {
            System.out.println("  [OK] Status updated to " + newStatus);
            System.out.println("  [NOTE] Trigger 'trg_audit_indicators' fired — audit log updated.");
        } else {
            System.out.println("  [WARN] No indicator found with ID " + id);
        }
        pause();
    }

    private void deleteIndicator() {
        clearScreen();
        System.out.println("\n  ═══ DELETE INDICATOR ═══");
        System.out.println("  [NOTE] Active Critical indicators cannot be deleted (trigger protection).");
        int id = promptInt("  Indicator ID to delete", 1, 99999);
        System.out.print("  Confirm delete ID=" + id + "? [yes/no]: ");
        if (!"yes".equalsIgnoreCase(sc.nextLine().trim())) return;

        try {
            db.executeUpdate("DELETE FROM indicators WHERE indicator_id = " + id);
            System.out.println("  [OK] Indicator deleted.");
        } catch (DatabaseException e) {
            System.out.println("  [BLOCKED] " + e.getMessage());
            System.out.println("  [NOTE] Trigger 'trg_prevent_critical_delete' blocked deletion.");
        }
        pause();
    }

    private void analyzeIndicator() {
        clearScreen();
        System.out.println("\n  ═══ ANALYZE INDICATOR ═══");
        System.out.println("  Using analyzer: " + analyzer.getAnalyzerName());
        int id = promptInt("  Indicator ID", 1, 99999);

        // Call PostgreSQL stored function
        String sql = "SELECT fn_indicator_risk_score(" + id + ") AS risk_score";
        try {
            List<Map<String,String>> rows = db.executeQuery(sql);
            if (!rows.isEmpty()) {
                String score = rows.get(0).get("risk_score");
                System.out.println("\n  Database Risk Score (fn_indicator_risk_score): " + score);
                double s = Double.parseDouble(score);
                System.out.println("  Classification: " + analyzer.classifyThreat(s));
            }
        } catch (Exception e) {
            System.out.println("  [ERROR] " + e.getMessage());
        }
        pause();
    }

    // ════════════════════════════════════════════
    //  2. THREAT ACTOR MANAGEMENT
    // ════════════════════════════════════════════
    private void menuThreatActors() {
        boolean back = false;
        while (!back) {
            clearScreen();
            System.out.println("\n  ═══════ THREAT ACTOR MANAGEMENT ═══════");
            System.out.println("  1. Add Threat Actor");
            System.out.println("  2. List All Actors");
            System.out.println("  3. View Actor Details + Indicators");
            System.out.println("  0. Back");
            System.out.print("\n  Choice: ");
            switch (sc.nextLine().trim()) {
                case "1" -> addThreatActor();
                case "2" -> listThreatActors();
                case "3" -> viewActorDetails();
                case "0" -> back = true;
            }
        }
    }

    private void addThreatActor() {
        clearScreen();
        System.out.println("\n  ── Add Threat Actor ──");
        String name          = prompt("  Actor Name");
        String type          = promptChoice("  Type [APT/Cybercriminal/Hacktivist/Insider/Script Kiddie/Nation-State]",
                                            "APT","Cybercriminal","Hacktivist","Insider","Script Kiddie","Nation-State");
        String country       = prompt("  Origin Country");
        String motivation    = prompt("  Motivation");
        int    sophistication = promptInt("  Sophistication Level (1-10)", 1, 10);
        String aliases       = prompt("  Aliases (comma-separated, optional)");
        String desc          = prompt("  Description");

        // Create Java OOP object
        ThreatActor actor = new ThreatActor(name, type, country, motivation, sophistication);
        actor.setAliases(aliases);
        actor.setDescription(desc);
        actor.display();

        System.out.print("\n  Save to database? [yes/no]: ");
        if (!"yes".equalsIgnoreCase(sc.nextLine().trim())) return;

        String sql = String.format(
            "INSERT INTO threat_actors (actor_name, actor_type, origin_country, motivation, " +
            "sophistication_level, aliases, description, created_by) " +
            "VALUES (%s, %s, %s, %s, %d, %s, %s, %d) RETURNING actor_id",
            db.escape(name), db.escape(type), db.escape(country), db.escape(motivation),
            sophistication, db.escape(aliases), db.escape(desc), currentUser.getUserId()
        );
        int newId = db.executeInsertReturning(sql);
        System.out.println("\n  [OK] Threat Actor saved. ID = " + newId);
        pause();
    }

    private void listThreatActors() {
        clearScreen();
        System.out.println("\n  ═══ ALL THREAT ACTORS ═══");
        // Demonstrates GROUP BY, COUNT, MAX — using the view
        String sql = "SELECT actor_id, actor_name, actor_type, origin_country, " +
                     "sophistication_level, total_indicators, incident_count, last_activity " +
                     "FROM vw_actor_summary ORDER BY sophistication_level DESC";
        List<Map<String,String>> rows = db.executeQuery(sql);
        DatabaseManager.printTable(rows);
        pause();
    }

    private void viewActorDetails() {
        clearScreen();
        int id = promptInt("  Actor ID", 1, 99999);
        // INNER JOIN with indicators
        String sql = "SELECT ta.actor_name, ta.actor_type, ta.origin_country, " +
                     "ta.sophistication_level, ta.motivation, ta.description, " +
                     "i.indicator_type, i.indicator_value, i.severity " +
                     "FROM threat_actors ta " +
                     "LEFT JOIN indicators i ON ta.actor_id = i.actor_id " +
                     "WHERE ta.actor_id = " + id;
        List<Map<String,String>> rows = db.executeQuery(sql);
        if (rows.isEmpty()) { System.out.println("  Actor not found."); pause(); return; }

        // Print actor info from first row
        Map<String,String> a = rows.get(0);
        System.out.println("\n  Actor  : " + a.get("actor_name"));
        System.out.println("  Type   : " + a.get("actor_type"));
        System.out.println("  Country: " + a.get("origin_country"));
        System.out.println("  Sophist: " + a.get("sophistication_level") + "/10");
        System.out.println("  Desc   : " + a.get("description"));
        System.out.println("\n  Associated Indicators:");
        DatabaseManager.printTable(rows.stream()
            .filter(r -> r.get("indicator_value") != null && !r.get("indicator_value").equals("NULL"))
            .collect(java.util.stream.Collectors.toList()));
        pause();
    }

    // ════════════════════════════════════════════
    //  3. MALWARE MANAGEMENT
    // ════════════════════════════════════════════
    private void menuMalware() {
        boolean back = false;
        while (!back) {
            clearScreen();
            System.out.println("\n  ═══════ MALWARE MANAGEMENT ═══════");
            System.out.println("  1. Add Malware Entry");
            System.out.println("  2. List Malware");
            System.out.println("  3. View by Type (BETWEEN/IN demo)");
            System.out.println("  0. Back");
            System.out.print("\n  Choice: ");
            switch (sc.nextLine().trim()) {
                case "1" -> addMalware();
                case "2" -> listMalware();
                case "3" -> malwareQueryDemo();
                case "0" -> back = true;
            }
        }
    }

    private void addMalware() {
        clearScreen();
        System.out.println("\n  ── Add Malware ──");
        String name   = prompt("  Malware Name");
        String family = prompt("  Malware Family");
        String type   = promptChoice("  Type [Ransomware/Trojan/Worm/Virus/Spyware/Rootkit/Adware/Botnet]",
                                     "Ransomware","Trojan","Worm","Virus","Spyware","Rootkit","Adware","Botnet");
        double score  = promptDouble("  Severity Score (0.0–10.0)");
        String platform = prompt("  Target Platform (Windows/Linux/Android)");
        String desc   = prompt("  Description");
        String behavior = prompt("  Behavior");
        String mitigate = prompt("  Mitigation");
        int    actorId  = promptInt("  Associated Threat Actor ID (0 if none)", 0, 9999);

        String actorRef = actorId > 0 ? String.valueOf(actorId) : "NULL";
        String sql = String.format(
            "INSERT INTO malware (malware_name, malware_family, malware_type, severity_score, " +
            "target_platform, description, behavior, mitigation, actor_id) " +
            "VALUES (%s, %s, %s, %.1f, %s, %s, %s, %s, %s) RETURNING malware_id",
            db.escape(name), db.escape(family), db.escape(type), score,
            db.escape(platform), db.escape(desc), db.escape(behavior),
            db.escape(mitigate), actorRef
        );
        int newId = db.executeInsertReturning(sql);
        System.out.println("\n  [OK] Malware entry saved. ID = " + newId);
        pause();
    }

    private void listMalware() {
        clearScreen();
        // Demonstrates LEFT JOIN, COALESCE, ORDER BY
        String sql = "SELECT m.malware_id, m.malware_name, m.malware_type, m.severity_score, " +
                     "m.target_platform, COALESCE(ta.actor_name, 'Unknown') AS actor " +
                     "FROM malware m LEFT JOIN threat_actors ta ON m.actor_id = ta.actor_id " +
                     "ORDER BY m.severity_score DESC";
        List<Map<String,String>> rows = db.executeQuery(sql);
        System.out.println("\n  ═══ MALWARE INVENTORY ═══");
        DatabaseManager.printTable(rows);
        pause();
    }

    private void malwareQueryDemo() {
        clearScreen();
        System.out.println("\n  ═══ SQL Demo: BETWEEN + IN Operators ═══");
        // BETWEEN demo
        System.out.println("\n  [BETWEEN] High-severity malware (score 7.0 to 10.0):");
        String sql1 = "SELECT malware_name, malware_type, severity_score " +
                      "FROM malware WHERE severity_score BETWEEN 7.0 AND 10.0 " +
                      "ORDER BY severity_score DESC";
        DatabaseManager.printTable(db.executeQuery(sql1));

        // IN demo
        System.out.println("\n  [IN] Only Ransomware and Trojan types:");
        String sql2 = "SELECT malware_name, malware_type, severity_score FROM malware " +
                      "WHERE malware_type IN ('Ransomware','Trojan') ORDER BY severity_score DESC";
        DatabaseManager.printTable(db.executeQuery(sql2));
        pause();
    }

    // ════════════════════════════════════════════
    //  4. VULNERABILITIES
    // ════════════════════════════════════════════
    private void menuVulnerabilities() {
        boolean back = false;
        while (!back) {
            clearScreen();
            System.out.println("\n  ═══════ VULNERABILITY TRACKING ═══════");
            System.out.println("  1. Add Vulnerability");
            System.out.println("  2. List All Vulnerabilities");
            System.out.println("  3. Unpatched Critical Vulns (Subquery demo)");
            System.out.println("  0. Back");
            System.out.print("\n  Choice: ");
            switch (sc.nextLine().trim()) {
                case "1" -> addVulnerability();
                case "2" -> listVulnerabilities();
                case "3" -> criticalVulnsDemo();
                case "0" -> back = true;
            }
        }
    }

    private void addVulnerability() {
        clearScreen();
        System.out.println("\n  ── Add Vulnerability ──");
        String cve      = prompt("  CVE ID (e.g. CVE-2024-1234, optional)");
        String title    = prompt("  Title");
        String desc     = prompt("  Description");
        double cvss     = promptDouble("  CVSS Score (0.0–10.0)");
        String product  = prompt("  Affected Product");
        String versions = prompt("  Affected Versions");
        String patched  = promptChoice("  Is Patched? [yes/no]", "yes","no");
        String patch_avail = promptChoice("  Patch Available? [yes/no]", "yes","no");
        String exploit  = promptChoice("  Exploit Available? [yes/no]", "yes","no");

        String cveRef = cve.isEmpty() ? "NULL" : db.escape(cve);
        String sql = String.format(
            "INSERT INTO vulnerabilities (cve_id, title, description, cvss_score, " +
            "affected_product, affected_versions, is_patched, patch_available, exploit_available) " +
            "VALUES (%s, %s, %s, %.1f, %s, %s, %s, %s, %s) RETURNING vuln_id",
            cveRef, db.escape(title), db.escape(desc), cvss,
            db.escape(product), db.escape(versions),
            "yes".equalsIgnoreCase(patched)     ? "TRUE":"FALSE",
            "yes".equalsIgnoreCase(patch_avail) ? "TRUE":"FALSE",
            "yes".equalsIgnoreCase(exploit)     ? "TRUE":"FALSE"
        );
        int newId = db.executeInsertReturning(sql);
        // NOTE: severity column is auto-computed by the database from cvss_score
        System.out.println("\n  [OK] Vulnerability saved. ID = " + newId);
        System.out.println("  [NOTE] Severity is auto-calculated by the DB from CVSS score.");
        pause();
    }

    private void listVulnerabilities() {
        clearScreen();
        // Demonstrates GENERATED ALWAYS (computed column) and ORDER BY CASE
        String sql = "SELECT vuln_id, cve_id, title, cvss_score, severity, " +
                     "is_patched, exploit_available FROM vulnerabilities " +
                     "ORDER BY cvss_score DESC";
        System.out.println("\n  ═══ VULNERABILITIES (severity auto-computed from CVSS) ═══");
        DatabaseManager.printTable(db.executeQuery(sql));
        pause();
    }

    private void criticalVulnsDemo() {
        clearScreen();
        System.out.println("\n  ═══ SQL Demo: Subquery — Unpatched above-average CVSS ═══");
        // Demonstrates subquery
        String sql = "SELECT cve_id, title, cvss_score, severity " +
                     "FROM vulnerabilities " +
                     "WHERE is_patched = FALSE " +
                     "  AND cvss_score > (SELECT AVG(cvss_score) FROM vulnerabilities) " +
                     "ORDER BY cvss_score DESC";
        System.out.println("  [SQL] WHERE cvss_score > (SELECT AVG(cvss_score) FROM vulnerabilities)");
        DatabaseManager.printTable(db.executeQuery(sql));

        // EXISTS demo
        System.out.println("\n  [EXISTS] Vulns that have exploit available:");
        String sql2 = "SELECT cve_id, title, cvss_score FROM vulnerabilities v " +
                      "WHERE EXISTS (SELECT 1 FROM vulnerabilities x " +
                      "WHERE x.vuln_id = v.vuln_id AND x.exploit_available = TRUE)";
        DatabaseManager.printTable(db.executeQuery(sql2));
        pause();
    }

    // ════════════════════════════════════════════
    //  5. INCIDENT MANAGEMENT
    // ════════════════════════════════════════════
    private void menuIncidents() {
        boolean back = false;
        while (!back) {
            clearScreen();
            System.out.println("\n  ═══════ INCIDENT MANAGEMENT ═══════");
            System.out.println("  1. Create Incident");
            System.out.println("  2. List Open Incidents");
            System.out.println("  3. Update Incident Status");
            System.out.println("  4. Link Indicator to Incident");
            System.out.println("  0. Back");
            System.out.print("\n  Choice: ");
            switch (sc.nextLine().trim()) {
                case "1" -> addIncident();
                case "2" -> listIncidents();
                case "3" -> updateIncidentStatus();
                case "4" -> linkIndicatorToIncident();
                case "0" -> back = true;
            }
        }
    }

    private void addIncident() {
        clearScreen();
        System.out.println("\n  ── Create Security Incident ──");
        String title     = prompt("  Incident Title");
        String desc      = prompt("  Description");
        String severity  = promptChoice("  Severity [Critical/High/Medium/Low]",
                                        "Critical","High","Medium","Low");
        String affected  = prompt("  Affected Systems");
        String impact    = prompt("  Impact Description");
        int    actorId   = promptInt("  Threat Actor ID (0 if unknown)", 0, 9999);
        int    assignTo  = promptInt("  Assign to Analyst (user_id, 0 to leave unassigned)", 0, 9999);

        String actorRef  = actorId  > 0 ? String.valueOf(actorId)  : "NULL";
        String assignRef = assignTo > 0 ? String.valueOf(assignTo) : "NULL";

        String sql = String.format(
            "INSERT INTO incidents (incident_title, description, severity, status, " +
            "affected_systems, impact_description, actor_id, assigned_to, reported_by) " +
            "VALUES (%s, %s, %s, 'Open', %s, %s, %s, %s, %d) RETURNING incident_id",
            db.escape(title), db.escape(desc), db.escape(severity),
            db.escape(affected), db.escape(impact),
            actorRef, assignRef, currentUser.getUserId()
        );
        int newId = db.executeInsertReturning(sql);
        System.out.println("\n  [OK] Incident created. ID = " + newId);
        pause();
    }

    private void listIncidents() {
        clearScreen();
        // Uses the view — multi-table JOIN + CASE (SLA check)
        String sql = "SELECT incident_id, incident_title, severity, status, " +
                     "threat_actor, assigned_analyst, open_days, sla_status " +
                     "FROM vw_open_incidents";
        System.out.println("\n  ═══ OPEN INCIDENTS (with SLA status) ═══");
        DatabaseManager.printTable(db.executeQuery(sql));
        pause();
    }

    private void updateIncidentStatus() {
        clearScreen();
        int    id     = promptInt("  Incident ID", 1, 99999);
        String status = promptChoice("  New Status [Open/In Progress/Resolved/Closed/False Positive]",
                                     "Open","In Progress","Resolved","Closed","False Positive");
        String notes  = prompt("  Resolution Notes (if resolving)");

        // When set to Resolved, trigger auto-sets resolved_at
        String sql = "UPDATE incidents SET status = " + db.escape(status) +
                     ", resolution_notes = " + db.escape(notes) +
                     " WHERE incident_id = " + id;
        db.executeUpdate(sql);
        System.out.println("  [OK] Status updated to: " + status);
        if ("Resolved".equals(status))
            System.out.println("  [NOTE] Trigger 'trg_update_incident_timestamp' auto-set resolved_at.");
        pause();
    }

    private void linkIndicatorToIncident() {
        clearScreen();
        int incidentId  = promptInt("  Incident ID", 1, 99999);
        int indicatorId = promptInt("  Indicator ID", 1, 99999);

        String sql = "INSERT INTO incident_indicators (incident_id, indicator_id) " +
                     "VALUES (" + incidentId + ", " + indicatorId + ")";
        try {
            db.executeUpdate(sql);
            System.out.println("  [OK] Indicator " + indicatorId + " linked to Incident " + incidentId);
        } catch (DatabaseException e) {
            System.out.println("  [ERROR] " + e.getMessage());
        }
        pause();
    }

    // ════════════════════════════════════════════
    //  6. REPORTS & ANALYTICS
    // ════════════════════════════════════════════
    private void menuReports() {
        boolean back = false;
        while (!back) {
            clearScreen();
            System.out.println("\n  ═══════ REPORTS & ANALYTICS ═══════");
            System.out.println("  1. Dashboard Summary");
            System.out.println("  2. Severity Statistics (GROUP BY + HAVING)");
            System.out.println("  3. Threat Actor Summary (JOIN + Aggregation)");
            System.out.println("  4. Window Functions Demo (ROW_NUMBER, RANK)");
            System.out.println("  5. JOIN Demo (INNER, LEFT, RIGHT)");
            System.out.println("  6. Subquery Demo (EXISTS, ALL, ANY)");
            System.out.println("  7. High-Activity Actors (Stored Function)");
            System.out.println("  0. Back");
            System.out.print("\n  Choice: ");
            switch (sc.nextLine().trim()) {
                case "1" -> dashboardView();
                case "2" -> severityStats();
                case "3" -> actorSummary();
                case "4" -> windowFunctionDemo();
                case "5" -> joinDemo();
                case "6" -> subqueryDemo();
                case "7" -> highActivityActors();
                case "0" -> back = true;
            }
        }
    }

    private void dashboardView() {
        clearScreen();
        System.out.println("\n  ═══ DASHBOARD SUMMARY ═══");
        List<Map<String,String>> rows = db.executeQuery("SELECT * FROM vw_dashboard");
        if (!rows.isEmpty()) {
            Map<String,String> d = rows.get(0);
            System.out.println("\n  Active Indicators    : " + d.getOrDefault("active_indicators","0"));
            System.out.println("  Critical IOCs        : " + d.getOrDefault("critical_indicators","0"));
            System.out.println("  Active Threat Actors : " + d.getOrDefault("active_actors","0"));
            System.out.println("  Open Incidents       : " + d.getOrDefault("open_incidents","0"));
            System.out.println("  In-Progress Incidents: " + d.getOrDefault("inprogress_incidents","0"));
            System.out.println("  Unpatched Vulns      : " + d.getOrDefault("unpatched_vulns","0"));
            System.out.println("  Total Malware Entries: " + d.getOrDefault("total_malware","0"));
            System.out.println("  Most Active Actor    : " + d.getOrDefault("most_active_actor","N/A"));
            System.out.println("  Avg Confidence Score : " + d.getOrDefault("avg_confidence","N/A") + "%");
        }
        pause();
    }

    private void severityStats() {
        clearScreen();
        System.out.println("\n  ═══ SEVERITY STATISTICS (GROUP BY, HAVING, AVG, COUNT) ═══");
        System.out.println("  [SQL] SELECT indicator_type, severity, COUNT(*), AVG(confidence_score)");
        System.out.println("        FROM indicators GROUP BY indicator_type, severity HAVING COUNT(*) > 0\n");
        DatabaseManager.printTable(db.executeQuery("SELECT * FROM vw_severity_stats"));
        pause();
    }

    private void actorSummary() {
        clearScreen();
        System.out.println("\n  ═══ THREAT ACTOR SUMMARY (LEFT JOIN, GROUP BY, COUNT, MAX) ═══");
        DatabaseManager.printTable(db.executeQuery("SELECT * FROM vw_actor_summary"));
        pause();
    }

    private void windowFunctionDemo() {
        clearScreen();
        System.out.println("\n  ═══ WINDOW FUNCTIONS: ROW_NUMBER, RANK, Running Total ═══");
        System.out.println("  [SQL] ROW_NUMBER OVER (PARTITION BY indicator_type ORDER BY confidence DESC)");
        System.out.println("        RANK OVER (ORDER BY confidence_score DESC)\n");
        String sql = "SELECT indicator_type, indicator_value, confidence_score, " +
                     "rank_in_type, overall_rank, pct_of_max " +
                     "FROM vw_indicator_ranking ORDER BY overall_rank LIMIT 20";
        DatabaseManager.printTable(db.executeQuery(sql));
        pause();
    }

    private void joinDemo() {
        clearScreen();
        System.out.println("\n  ═══ SQL JOIN DEMO ═══");

        System.out.println("\n  [INNER JOIN] Only indicators WITH known threat actors:");
        System.out.println("  (Excludes indicators where actor_id IS NULL)\n");
        String inner = "SELECT i.indicator_type, i.indicator_value, i.severity, ta.actor_name " +
                       "FROM indicators i INNER JOIN threat_actors ta ON i.actor_id = ta.actor_id";
        DatabaseManager.printTable(db.executeQuery(inner));

        System.out.println("\n  [LEFT JOIN] ALL indicators (unknown actor shown as 'Unknown'):");
        String left = "SELECT i.indicator_type, i.indicator_value, i.severity, " +
                      "COALESCE(ta.actor_name,'Unknown') AS actor " +
                      "FROM indicators i LEFT JOIN threat_actors ta ON i.actor_id = ta.actor_id";
        DatabaseManager.printTable(db.executeQuery(left));

        System.out.println("\n  [RIGHT JOIN] All threat actors (even those without any indicators):");
        String right = "SELECT ta.actor_name, ta.actor_type, " +
                       "COALESCE(i.indicator_value,'(none)') AS indicator " +
                       "FROM indicators i RIGHT JOIN threat_actors ta ON i.actor_id = ta.actor_id " +
                       "ORDER BY ta.actor_name";
        DatabaseManager.printTable(db.executeQuery(right));
        pause();
    }

    private void subqueryDemo() {
        clearScreen();
        System.out.println("\n  ═══ SUBQUERY DEMO: EXISTS, Correlated, Scalar ═══");

        System.out.println("\n  [SCALAR SUBQUERY] Indicators above average confidence:");
        String sql1 = "SELECT indicator_type, indicator_value, confidence_score FROM indicators " +
                      "WHERE confidence_score > (SELECT AVG(confidence_score) FROM indicators) " +
                      "ORDER BY confidence_score DESC";
        DatabaseManager.printTable(db.executeQuery(sql1));

        System.out.println("\n  [EXISTS] Actors that have at least one indicator linked:");
        String sql2 = "SELECT actor_name, actor_type FROM threat_actors ta " +
                      "WHERE EXISTS (SELECT 1 FROM indicators i WHERE i.actor_id = ta.actor_id)";
        DatabaseManager.printTable(db.executeQuery(sql2));
        pause();
    }

    private void highActivityActors() {
        clearScreen();
        System.out.println("\n  ═══ HIGH-ACTIVITY ACTORS (Stored Function + Subquery) ═══");
        System.out.println("  [SQL] Calls fn_high_activity_actors() — actors with above-average indicators");
        String sql = "SELECT * FROM fn_high_activity_actors()";
        DatabaseManager.printTable(db.executeQuery(sql));
        pause();
    }

    // ════════════════════════════════════════════
    //  7. AUDIT LOG
    // ════════════════════════════════════════════
    private void viewAuditLog() {
        clearScreen();
        System.out.println("\n  ═══ AUDIT LOG (Auto-populated by Triggers) ═══");
        System.out.println("  Every INSERT, UPDATE, DELETE on indicators and threat_actors");
        System.out.println("  is automatically recorded here by database triggers.\n");
        String sql = "SELECT log_id, table_name, operation, record_id, " +
                     "old_data, new_data, performed_at " +
                     "FROM audit_log ORDER BY performed_at DESC LIMIT 30";
        DatabaseManager.printTable(db.executeQuery(sql));
        pause();
    }

    // ════════════════════════════════════════════
    //  UTILITY METHODS
    // ════════════════════════════════════════════
    private void clearScreen() {
        System.out.print("\033[H\033[2J");
        System.out.flush();
    }

    private void printBanner() {
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║   CYBER THREAT INTELLIGENCE MANAGEMENT SYSTEM (CTIMS)       ║");
        System.out.println("║   Amrita — Advanced Programming & Database Management System ║");
        System.out.println("║   P VARSHITH REDDY (CH.SC.U4CYS25022)                       ║");
        System.out.println("║   A ROHAN KARTHIK REDDY (CH.SC.Y4CYS25002)                  ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }

    private void pause() {
        System.out.print("\n  Press ENTER to continue...");
        sc.nextLine();
    }

    private String prompt(String msg) {
        System.out.print(msg + ": ");
        return sc.nextLine().trim();
    }

    private String promptChoice(String msg, String... options) {
        System.out.print(msg + ": ");
        String input = sc.nextLine().trim();
        for (String opt : options) if (opt.equalsIgnoreCase(input)) return opt;
        return options[0];  // Default to first option if invalid input
    }

    private int promptInt(String msg, int min, int max) {
        while (true) {
            System.out.print(msg + ": ");
            try {
                int val = Integer.parseInt(sc.nextLine().trim());
                if (val >= min && val <= max) return val;
            } catch (NumberFormatException ignored) {}
            System.out.println("  Please enter a number between " + min + " and " + max);
        }
    }

    private long promptLong(String msg) {
        System.out.print(msg + ": ");
        try { return Long.parseLong(sc.nextLine().trim()); }
        catch (Exception e) { return 0; }
    }

    private double promptDouble(String msg) {
        System.out.print(msg + ": ");
        try { return Double.parseDouble(sc.nextLine().trim()); }
        catch (Exception e) { return 0.0; }
    }

    // ════════════════════════════════════════════
    //  ENTRY POINT
    // ════════════════════════════════════════════
    public static void main(String[] args) {
        System.out.println("\n  Starting CTIMS...");

        try {
            CTIMS app = new CTIMS();

            // Login loop — max 3 attempts
            int attempts = 0;
            boolean loggedIn = false;
            while (attempts < 3 && !loggedIn) {
                loggedIn = app.login();
                if (!loggedIn) {
                    attempts++;
                    System.out.println("  Attempt " + attempts + "/3");
                    if (attempts < 3) {
                        try { Thread.sleep(1000); } catch (Exception e2) {}
                    }
                }
            }

            if (!loggedIn) {
                System.out.println("\n  Too many failed attempts. Exiting.");
                return;
            }

            app.run();

        } catch (DatabaseException e) {
            System.err.println("\n  [FATAL DB ERROR] " + e.getMessage());
            System.err.println("  Check your internet connection and Neon DB credentials.");
        } catch (Exception e) {
            System.err.println("\n  [FATAL ERROR] " + e.getMessage());
            e.printStackTrace();
        }
    }
}
