#pragma once
// ============================================================
//  DatabaseManager — Singleton Pattern
//  Manages the single PostgreSQL connection for the entire app.
//  Demonstrates: Singleton, encapsulation, RAII, exceptions
// ============================================================
#include <string>
#include <vector>
#include <map>
#include <stdexcept>
#include <libpq-fe.h>

// Custom exception for database errors
class DatabaseException : public std::runtime_error {
public:
    explicit DatabaseException(const std::string& msg)
        : std::runtime_error("DB Error: " + msg) {}
};

// Row = map<column_name, value>
using Row    = std::map<std::string, std::string>;
using Result = std::vector<Row>;

class DatabaseManager {
private:
    // ── Singleton: private constructor prevents external instantiation ──
    static DatabaseManager* instance_;

    PGconn*     conn_;          // libpq connection handle
    std::string conn_str_;

    explicit DatabaseManager(const std::string& conn_str);

    // Delete copy constructor and assignment (Singleton rule)
    DatabaseManager(const DatabaseManager&)            = delete;
    DatabaseManager& operator=(const DatabaseManager&) = delete;

public:
    ~DatabaseManager();

    // ── Singleton accessor ──
    static DatabaseManager* getInstance(const std::string& conn_str = "");
    static void             destroyInstance();

    // ── Connection ──
    bool isConnected() const;
    void reconnect();

    // ── Query execution ──
    Result executeQuery(const std::string& sql);
    bool   executeNonQuery(const std::string& sql);
    int    executeReturningId(const std::string& sql);  // INSERT … RETURNING id

    // ── Transaction control ──
    void beginTransaction();
    void commitTransaction();
    void rollbackTransaction();

    // ── Utility: escape string to prevent SQL injection ──
    std::string escape(const std::string& input);

    // ── Helper: print query result as ASCII table ──
    static void printResult(const Result& rows);
};
