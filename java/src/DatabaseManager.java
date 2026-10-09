import java.sql.*;
import java.util.*;

// ============================================================
//  DatabaseManager — Singleton Pattern
//  One single database connection shared across the whole app.
//  OOP Concepts: Singleton, Encapsulation, Exception Handling
// ============================================================
public class DatabaseManager {

    // ── Singleton: only one instance allowed ──
    private static DatabaseManager instance = null;

    private Connection connection;

    // Neon PostgreSQL credentials
    private static final String HOST     = "ep-muddy-sea-b4anq2mq-pooler.c-6.us-east-2.aws.neon.tech";
    private static final String DB       = "neondb";
    private static final String USER     = "neondb_owner";
    private static final String PASSWORD = "npg_8Tbm4ChDXQqf";
    private static final String URL      =
        "jdbc:postgresql://" + HOST + "/" + DB + "?sslmode=require";

    // Private constructor — prevents direct instantiation
    private DatabaseManager() {
        try {
            Class.forName("org.postgresql.Driver");
            Properties props = new Properties();
            props.setProperty("user", USER);
            props.setProperty("password", PASSWORD);
            props.setProperty("ssl", "true");
            props.setProperty("sslmode", "require");
            connection = DriverManager.getConnection(URL, props);
            System.out.println("[DB] Connected to Neon PostgreSQL successfully.");
        } catch (Exception e) {
            throw new DatabaseException("Connection failed: " + e.getMessage(), e);
        }
    }

    // ── Singleton accessor (thread-safe) ──
    public static synchronized DatabaseManager getInstance() {
        if (instance == null) {
            instance = new DatabaseManager();
        }
        return instance;
    }

    public boolean isConnected() {
        try {
            return connection != null && !connection.isClosed();
        } catch (SQLException e) {
            return false;
        }
    }

    // ── Execute SELECT queries — returns list of rows as maps ──
    public List<Map<String, String>> executeQuery(String sql) {
        List<Map<String, String>> rows = new ArrayList<>();
        try (Statement stmt = connection.createStatement();
             ResultSet rs   = stmt.executeQuery(sql)) {

            ResultSetMetaData meta = rs.getMetaData();
            int cols = meta.getColumnCount();

            while (rs.next()) {
                Map<String, String> row = new LinkedHashMap<>();
                for (int i = 1; i <= cols; i++) {
                    String col = meta.getColumnName(i);
                    String val = rs.getString(i);
                    row.put(col, val == null ? "NULL" : val);
                }
                rows.add(row);
            }
        } catch (SQLException e) {
            throw new DatabaseException("Query failed: " + e.getMessage(), sql);
        }
        return rows;
    }

    // ── Execute INSERT/UPDATE/DELETE ──
    public int executeUpdate(String sql) {
        try (Statement stmt = connection.createStatement()) {
            return stmt.executeUpdate(sql);
        } catch (SQLException e) {
            throw new DatabaseException("Update failed: " + e.getMessage(), sql);
        }
    }

    // ── Execute INSERT … RETURNING id ──
    public int executeInsertReturning(String sql) {
        try (Statement stmt = connection.createStatement();
             ResultSet rs   = stmt.executeQuery(sql)) {
            if (rs.next()) return rs.getInt(1);
            return -1;
        } catch (SQLException e) {
            throw new DatabaseException("Insert failed: " + e.getMessage(), sql);
        }
    }

    // ── Transaction control ──
    public void beginTransaction() {
        try { connection.setAutoCommit(false); }
        catch (SQLException e) { throw new DatabaseException("Begin transaction failed", e); }
    }

    public void commitTransaction() {
        try {
            connection.commit();
            connection.setAutoCommit(true);
        } catch (SQLException e) { throw new DatabaseException("Commit failed", e); }
    }

    public void rollbackTransaction() {
        try {
            connection.rollback();
            connection.setAutoCommit(true);
        } catch (SQLException e) { /* ignore rollback errors */ }
    }

    // ── Escape strings to prevent SQL injection ──
    public String escape(String input) {
        if (input == null) return "NULL";
        return "'" + input.replace("'", "''") + "'";
    }

    // ── Pretty print a result set as an ASCII table ──
    public static void printTable(List<Map<String, String>> rows) {
        if (rows.isEmpty()) {
            System.out.println("  (no rows returned)");
            return;
        }

        // Column order from first row
        List<String> cols = new ArrayList<>(rows.get(0).keySet());
        Map<String, Integer> widths = new LinkedHashMap<>();
        for (String c : cols) widths.put(c, c.length());
        for (Map<String, String> row : rows)
            for (String c : cols)
                widths.put(c, Math.max(widths.get(c), row.getOrDefault(c, "").length()));

        // Build separator line
        StringBuilder sep = new StringBuilder("+");
        for (String c : cols) sep.append("-".repeat(widths.get(c) + 2)).append("+");

        System.out.println(sep);
        System.out.print("| ");
        for (String c : cols) System.out.printf("%-" + widths.get(c) + "s | ", c);
        System.out.println("\n" + sep);

        for (Map<String, String> row : rows) {
            System.out.print("| ");
            for (String c : cols)
                System.out.printf("%-" + widths.get(c) + "s | ", row.getOrDefault(c, ""));
            System.out.println();
        }
        System.out.println(sep);
        System.out.println("  " + rows.size() + " row(s)");
    }

    public void close() {
        try { if (connection != null) connection.close(); }
        catch (SQLException e) { /* ignore */ }
    }
}
