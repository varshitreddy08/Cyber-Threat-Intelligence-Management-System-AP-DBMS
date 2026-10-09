#include "../include/DatabaseManager.h"
#include <iostream>
#include <iomanip>
#include <algorithm>

// ── Static member initialization ──
DatabaseManager* DatabaseManager::instance_ = nullptr;

// ── Private constructor ──
DatabaseManager::DatabaseManager(const std::string& conn_str)
    : conn_(nullptr), conn_str_(conn_str)
{
    conn_ = PQconnectdb(conn_str_.c_str());
    if (PQstatus(conn_) != CONNECTION_OK) {
        std::string err = PQerrorMessage(conn_);
        PQfinish(conn_);
        conn_ = nullptr;
        throw DatabaseException("Connection failed: " + err);
    }
    std::cout << "[DB] Connected to PostgreSQL successfully.\n";
}

DatabaseManager::~DatabaseManager() {
    if (conn_) {
        PQfinish(conn_);
        conn_ = nullptr;
    }
}

// ── Singleton accessor ──
DatabaseManager* DatabaseManager::getInstance(const std::string& conn_str) {
    if (!instance_) {
        if (conn_str.empty())
            throw DatabaseException("Connection string required for first call.");
        instance_ = new DatabaseManager(conn_str);
    }
    return instance_;
}

void DatabaseManager::destroyInstance() {
    delete instance_;
    instance_ = nullptr;
}

bool DatabaseManager::isConnected() const {
    return conn_ != nullptr && PQstatus(conn_) == CONNECTION_OK;
}

void DatabaseManager::reconnect() {
    if (conn_) PQreset(conn_);
    if (PQstatus(conn_) != CONNECTION_OK)
        throw DatabaseException("Reconnection failed: " + std::string(PQerrorMessage(conn_)));
}

// ── Execute SELECT and return rows ──
Result DatabaseManager::executeQuery(const std::string& sql) {
    if (!isConnected()) reconnect();

    PGresult* res = PQexec(conn_, sql.c_str());
    Result rows;

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        std::string err = PQresultErrorMessage(res);
        PQclear(res);
        throw DatabaseException(err);
    }

    int ncols = PQnfields(res);
    int nrows = PQntuples(res);

    for (int r = 0; r < nrows; ++r) {
        Row row;
        for (int c = 0; c < ncols; ++c) {
            std::string col_name = PQfname(res, c);
            std::string value    = PQgetisnull(res, r, c) ? "NULL" : PQgetvalue(res, r, c);
            row[col_name] = value;
        }
        rows.push_back(row);
    }

    PQclear(res);
    return rows;
}

// ── Execute INSERT/UPDATE/DELETE ──
bool DatabaseManager::executeNonQuery(const std::string& sql) {
    if (!isConnected()) reconnect();

    PGresult* res = PQexec(conn_, sql.c_str());
    bool ok = (PQresultStatus(res) == PGRES_COMMAND_OK);

    if (!ok) {
        std::string err = PQresultErrorMessage(res);
        PQclear(res);
        throw DatabaseException(err);
    }

    PQclear(res);
    return true;
}

// ── Execute INSERT … RETURNING id ──
int DatabaseManager::executeReturningId(const std::string& sql) {
    if (!isConnected()) reconnect();

    PGresult* res = PQexec(conn_, sql.c_str());

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        std::string err = PQresultErrorMessage(res);
        PQclear(res);
        throw DatabaseException(err);
    }

    int id = 0;
    if (PQntuples(res) > 0)
        id = std::stoi(PQgetvalue(res, 0, 0));

    PQclear(res);
    return id;
}

// ── Transaction control ──
void DatabaseManager::beginTransaction()  { executeNonQuery("BEGIN;"); }
void DatabaseManager::commitTransaction() { executeNonQuery("COMMIT;"); }
void DatabaseManager::rollbackTransaction() {
    try { executeNonQuery("ROLLBACK;"); }
    catch (...) {}
}

// ── Escape input to prevent SQL injection ──
std::string DatabaseManager::escape(const std::string& input) {
    if (!isConnected()) return input;
    char* escaped = PQescapeLiteral(conn_, input.c_str(), input.size());
    if (!escaped) return "''";
    std::string result(escaped);
    PQfreemem(escaped);
    return result;
}

// ── Pretty-print result as ASCII table ──
void DatabaseManager::printResult(const Result& rows) {
    if (rows.empty()) {
        std::cout << "(no rows)\n";
        return;
    }

    // Collect column names and widths
    std::vector<std::string> cols;
    for (const auto& kv : rows[0]) cols.push_back(kv.first);

    std::map<std::string, size_t> widths;
    for (const auto& col : cols) widths[col] = col.size();
    for (const auto& row : rows)
        for (const auto& col : cols)
            if (row.count(col)) widths[col] = std::max(widths[col], row.at(col).size());

    // Header
    std::string sep = "+";
    for (const auto& col : cols) sep += std::string(widths[col] + 2, '-') + "+";
    std::cout << sep << "\n| ";
    for (const auto& col : cols)
        std::cout << std::left << std::setw(static_cast<int>(widths[col])) << col << " | ";
    std::cout << "\n" << sep << "\n";

    // Rows
    for (const auto& row : rows) {
        std::cout << "| ";
        for (const auto& col : cols) {
            std::string val = row.count(col) ? row.at(col) : "";
            std::cout << std::left << std::setw(static_cast<int>(widths[col])) << val << " | ";
        }
        std::cout << "\n";
    }
    std::cout << sep << "\n";
    std::cout << rows.size() << " row(s)\n";
}
