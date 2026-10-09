// ============================================================
//  ThreatAnalyzer — Abstract class (Strategy Pattern)
//  OOP Concepts: Abstraction, Strategy pattern,
//                Multiple concrete implementations
// ============================================================
import java.util.List;

public abstract class ThreatAnalyzer {

    // ── Abstract methods — each strategy implements differently ──
    public abstract double calculateRiskScore(Indicator ind);
    public abstract String classifyThreat(double score);
    public abstract String generateReport(List<Indicator> indicators);
    public abstract String getAnalyzerName();

    // ── Common method shared by all analyzers ──
    protected String formatScore(double score) {
        return String.format("%.2f / 10.00", score);
    }
}

// ============================================================
//  BasicAnalyzer — Simple severity-based scoring
// ============================================================
class BasicAnalyzer extends ThreatAnalyzer {

    @Override
    public double calculateRiskScore(Indicator ind) {
        return ind.analyze();   // Delegates to each indicator's own analysis
    }

    @Override
    public String classifyThreat(double score) {
        if (score >= 8.0) return "CRITICAL THREAT";
        if (score >= 6.0) return "HIGH THREAT";
        if (score >= 4.0) return "MEDIUM THREAT";
        return "LOW THREAT";
    }

    @Override
    public String generateReport(List<Indicator> indicators) {
        StringBuilder sb = new StringBuilder();
        sb.append("\n=== Basic Threat Analysis Report ===\n");
        sb.append("Total indicators analyzed: ").append(indicators.size()).append("\n");
        int critical = 0, high = 0, medium = 0, low = 0;
        for (Indicator ind : indicators) {
            switch (ind.getSeverity()) {
                case "Critical" -> critical++;
                case "High"     -> high++;
                case "Medium"   -> medium++;
                default         -> low++;
            }
        }
        sb.append("Critical: ").append(critical).append("\n");
        sb.append("High    : ").append(high).append("\n");
        sb.append("Medium  : ").append(medium).append("\n");
        sb.append("Low     : ").append(low).append("\n");
        return sb.toString();
    }

    @Override
    public String getAnalyzerName() { return "Basic Analyzer"; }
}

// ============================================================
//  AdvancedAnalyzer — Weighted multi-factor scoring
// ============================================================
class AdvancedAnalyzer extends ThreatAnalyzer {

    @Override
    public double calculateRiskScore(Indicator ind) {
        double base = ind.analyze();
        double confidence_weight = ind.getConfidence() / 100.0;
        double malicious_bonus   = ind.isMalicious() ? 1.0 : 0.0;
        return Math.min((base * 0.7) + (confidence_weight * 2.0) + malicious_bonus, 10.0);
    }

    @Override
    public String classifyThreat(double score) {
        if (score >= 9.0) return "CRITICAL — IMMEDIATE ACTION REQUIRED";
        if (score >= 7.0) return "HIGH — ACTION REQUIRED WITHIN 24 HOURS";
        if (score >= 5.0) return "MEDIUM — ACTION REQUIRED WITHIN 7 DAYS";
        if (score >= 3.0) return "LOW — MONITOR";
        return "INFORMATIONAL";
    }

    @Override
    public String generateReport(List<Indicator> indicators) {
        StringBuilder sb = new StringBuilder();
        sb.append("\n=== Advanced Threat Analysis Report ===\n");
        double totalRisk = 0;
        Indicator highest = null;
        for (Indicator ind : indicators) {
            double score = calculateRiskScore(ind);
            totalRisk += score;
            if (highest == null || score > calculateRiskScore(highest))
                highest = ind;
        }
        sb.append("Indicators Analyzed : ").append(indicators.size()).append("\n");
        if (!indicators.isEmpty()) {
            sb.append("Average Risk Score  : ").append(
                formatScore(totalRisk / indicators.size())).append("\n");
        }
        if (highest != null) {
            sb.append("Highest Risk IOC    : ").append(highest.getValue()).append(
                " (Score: ").append(formatScore(calculateRiskScore(highest))).append(")\n");
            sb.append("Classification      : ").append(
                classifyThreat(calculateRiskScore(highest))).append("\n");
        }
        return sb.toString();
    }

    @Override
    public String getAnalyzerName() { return "Advanced Analyzer"; }
}
