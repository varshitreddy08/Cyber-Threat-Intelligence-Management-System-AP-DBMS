#pragma once
// ============================================================
//  ThreatAnalyzer — Abstract class (Strategy Pattern)
//  Demonstrates: Abstraction, strategy pattern,
//                pure virtual functions, multiple derived classes
// ============================================================
#include <string>
#include <vector>
#include <memory>
#include "Indicator.h"

class ThreatAnalyzer {
public:
    virtual ~ThreatAnalyzer() = default;

    // ── Pure virtual strategy methods ──
    virtual double      calculateRiskScore(const Indicator& ind)                          const = 0;
    virtual std::string classifyThreat(double score)                                      const = 0;
    virtual std::string generateReport(const std::vector<std::shared_ptr<Indicator>>& v)  const = 0;
    virtual std::string getAnalyzerName()                                                 const = 0;
};

// ── Concrete Strategy 1: Simple scoring ──
class BasicAnalyzer : public ThreatAnalyzer {
public:
    double      calculateRiskScore(const Indicator& ind) const override;
    std::string classifyThreat(double score)             const override;
    std::string generateReport(const std::vector<std::shared_ptr<Indicator>>& v) const override;
    std::string getAnalyzerName() const override { return "Basic Analyzer"; }
};

// ── Concrete Strategy 2: Advanced weighted scoring ──
class AdvancedAnalyzer : public ThreatAnalyzer {
public:
    double      calculateRiskScore(const Indicator& ind) const override;
    std::string classifyThreat(double score)             const override;
    std::string generateReport(const std::vector<std::shared_ptr<Indicator>>& v) const override;
    std::string getAnalyzerName() const override { return "Advanced Analyzer"; }
};
