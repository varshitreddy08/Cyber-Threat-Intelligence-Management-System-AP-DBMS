// ============================================================
//  Custom Exception — demonstrates Exception Handling in Java OOP
// ============================================================
public class DatabaseException extends RuntimeException {
    private final String query;

    public DatabaseException(String message) {
        super(message);
        this.query = null;
    }

    public DatabaseException(String message, String query) {
        super(message);
        this.query = query;
    }

    public DatabaseException(String message, Throwable cause) {
        super(message, cause);
        this.query = null;
    }

    public String getQuery() { return query; }

    @Override
    public String toString() {
        return "DatabaseException: " + getMessage() +
               (query != null ? "\nQuery: " + query : "");
    }
}
