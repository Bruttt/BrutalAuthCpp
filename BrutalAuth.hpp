#pragma once
#include <string>

class BrutalAuth {
public:
    
    explicit BrutalAuth(std::string applicationId,
        std::string host = "api.brutalauth.site");


    bool registerUser(const std::string& licenseKey,
        const std::string& username,
        const std::string& password);


    bool loginUser(const std::string& username,
        const std::string& password);

private:
    std::string applicationId_;
    std::string host_; 


    static std::string makeJsonRegister(const std::string& licenseKey,
        const std::string& username,
        const std::string& password,
        const std::string& hwid,
        const std::string& applicationId);

    static std::string makeJsonLogin(const std::string& username,
        const std::string& password,
        const std::string& hwid,
        const std::string& applicationId);

    bool postJson(const std::string& pathOrUrl,
        const std::string& body,
        std::string& out);

    static bool contains_success_true(const std::string& body);
};
