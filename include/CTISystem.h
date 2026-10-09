#pragma once
// ============================================================
//  CTISystem — Facade Pattern (main application controller)
//  Demonstrates: Facade pattern, unique_ptr, shared_ptr,
//                template function, all OOP features combined
// ============================================================
#include <string>
#include <memory>
#include <vector>
#include "DatabaseManager.h"
#include "User.h"
#include "Indicator.h"
#include "ThreatActor.h"
#include "ThreatAnalyzer.h"

class CTISystem {
private:
    DatabaseManager*                   db_;
    std::unique_ptr<ThreatAnalyzer>    analyzer_;
    std::vector<std::shared_ptr<User>> users_;
    User*                              current_user_;

    static const std::string DB_CONN_STR;

    // ── Private helpers ──
    void clearScreen()             const;
    void printHeader()             const;
    void printSeparator(char c = '-', int width = 70) const;
    void pressEnterToContinue()    const;
    std::string getInput(const std::string& prompt) const;
    int  getIntInput(const std::string& prompt, int min = 0, int max = 100) const;

    // ── Template helper: display any item that has display() ──
    template<typename T>
    void displayAll(const std::vector<std::shared_ptr<T>>& items) const {
        for (const auto& item : items) item->display();
    }

public:
    CTISystem();
    ~CTISystem();

    // ── Authentication ──
    bool login(const std::string& username, const std::string& password);
    void logout();

    // ── Main menu ──
    void run();

    // ── Indicator management ──
    void menuIndicators();
    void addIndicator();
    void listIndicators();
    void searchIndicators();
    void updateIndicatorStatus();
    void deleteIndicator();
    void analyzeIndicator();

    // ── Threat Actor management ──
    void menuThreatActors();
    void addThreatActor();
    void listThreatActors();
    void viewActorDetails();

    // ── Malware management ──
    void menuMalware();
    void listMalware();
    void addMalware();

    // ── Vulnerability tracking ──
    void menuVulnerabilities();
    void listVulnerabilities();

    // ── Incident management ──
    void menuIncidents();
    void listIncidents();
    void addIncident();
    void updateIncidentStatus();

    // ── Reports & Analytics ──
    void menuReports();
    void dashboardView();
    void severityStatistics();
    void actorSummary();
    void windowFunctionDemo();
    void joinDemo();
    void auditLog();

    // ── Database setup ──
    bool setupDatabase();
};
