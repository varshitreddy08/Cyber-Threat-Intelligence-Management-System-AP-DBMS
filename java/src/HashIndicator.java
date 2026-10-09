// ============================================================
//  HashIndicator — extends Indicator (Inheritance + Polymorphism)
// ============================================================
public class HashIndicator extends Indicator {

    private String hashType;       // MD5, SHA1, SHA256, SHA512
    private String fileName;
    private long   fileSizeBytes;

    public HashIndicator(String hash, String severity, boolean malicious,
                         int confidence, String hashType, String fileName, long fileSize) {
        super(hash, severity, malicious, confidence);
        this.hashType      = hashType;
        this.fileName      = fileName;
        this.fileSizeBytes = fileSize;
    }

    @Override
    public String getType() { return "Hash"; }

    @Override
    public double analyze() {
        double score = switch (severity) {
            case "Critical" -> 5.0;
            case "High"     -> 4.0;
            case "Medium"   -> 3.0;
            default         -> 1.5;
        };
        score += (confidenceScore / 100.0) * 3.0;
        // MD5 is weaker — slightly lower certainty
        if ("MD5".equals(hashType))  score += 0.3;
        if ("SHA256".equals(hashType) || "SHA512".equals(hashType)) score += 0.5;
        return Math.min(score, 10.0);
    }

    @Override
    public String getDescription() {
        String size = fileSizeBytes > 0 ? fileSizeBytes + " bytes" : "Unknown size";
        return String.format("File Hash [%s]: %s | File: %s (%s)",
                hashType, value.length() > 20 ? value.substring(0,20) + "…" : value,
                fileName.isEmpty() ? "Unknown" : fileName, size);
    }

    @Override
    public void display() {
        printLine(60);
        System.out.println("  TYPE        : File Hash");
        System.out.println("  HASH TYPE   : " + hashType);
        System.out.println("  HASH VALUE  : " + value);
        System.out.println("  FILE NAME   : " + (fileName.isEmpty() ? "Unknown" : fileName));
        System.out.println("  FILE SIZE   : " + (fileSizeBytes > 0 ? fileSizeBytes + " bytes" : "Unknown"));
        System.out.println("  SEVERITY    : " + getSeverityLabel());
        System.out.println("  CONFIDENCE  : " + confidenceScore + "%");
        System.out.println("  MALICIOUS   : " + (isMalicious ? "YES" : "NO"));
        System.out.printf ("  RISK SCORE  : %.2f / 10.0%n", analyze());
        if (!context.isEmpty()) System.out.println("  CONTEXT     : " + context);
        printLine(60);
    }

    public boolean validateLength() {
        return switch (hashType) {
            case "MD5"    -> value.length() == 32;
            case "SHA1"   -> value.length() == 40;
            case "SHA256" -> value.length() == 64;
            case "SHA512" -> value.length() == 128;
            default       -> true;
        };
    }

    public String getHashType()      { return hashType; }
    public String getFileName()      { return fileName; }
    public long   getFileSizeBytes() { return fileSizeBytes; }
}
