#pragma once
// ============================================================
//  URLIndicator — Derived from Indicator (Inheritance)
// ============================================================
#include "Indicator.h"

class URLIndicator : public Indicator {
private:
    std::string protocol_;       // http / https / ftp
    std::string host_;
    std::string path_;
    bool        has_redirect_;

public:
    URLIndicator(const std::string& url,
                 const std::string& severity     = "Medium",
                 bool               malicious    = true,
                 int                confidence   = 50,
                 bool               has_redirect = false);

    std::string getType()        const override { return "URL"; }
    double      analyze()        const override;
    std::string getDescription() const override;
    void        display()        const override;

    std::string getProtocol()    const { return protocol_; }
    std::string getHost()        const { return host_; }
    std::string getPath()        const { return path_; }
    bool        hasRedirect()    const { return has_redirect_; }

private:
    void parseURL(const std::string& url);
};
