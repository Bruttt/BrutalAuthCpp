#include "BrutalAuth.hpp"

#include <iostream>
#include <sstream>
#include <fstream>
#include <memory>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#include <sddl.h>        // ConvertSidToStringSid
#include <wtsapi32.h>    // WTS*
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Wtsapi32.lib")
#elif __linux__
#include <curl/curl.h>
#endif

// -------------------- file-local helpers (not part of class) --------------------
namespace {

#ifdef _WIN32
    std::wstring to_wide(const std::string& s) {
        if (s.empty()) return L"";
        int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
        std::wstring w(len, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], len);
        return w;
    }

    static std::string SidToString(PSID sid) {
        if (!sid || !IsValidSid(sid)) return {};
        LPSTR sidStr = nullptr;
        if (!ConvertSidToStringSidA(sid, &sidStr)) return {};
        std::string out = sidStr;
        LocalFree(sidStr);
        return out;
    }

    static std::string SidFromToken(HANDLE hToken) {
        if (!hToken) return {};
        DWORD len = 0;
        GetTokenInformation(hToken, TokenUser, nullptr, 0, &len);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return {};
        auto buf = std::unique_ptr<BYTE[]>(new BYTE[len]);
        if (!GetTokenInformation(hToken, TokenUser, buf.get(), len, &len)) return {};
        TOKEN_USER* tu = reinterpret_cast<TOKEN_USER*>(buf.get());
        return SidToString(tu->User.Sid);
    }

    static std::string SidFromActiveSessionToken() {
        // 1) active console session
        DWORD sessionId = WTSGetActiveConsoleSessionId();
        if (sessionId != 0xFFFFFFFF) {
            HANDLE hToken = nullptr;
            if (WTSQueryUserToken(sessionId, &hToken)) {
                std::string sid = SidFromToken(hToken);
                CloseHandle(hToken);
                if (!sid.empty()) return sid;
            }
        }
        // 2) enumerate sessions
        WTS_SESSION_INFOA* sessions = nullptr;
        DWORD count = 0;
        if (WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count)) {
            for (DWORD i = 0; i < count; ++i) {
                if (sessions[i].State == WTSActive) {
                    HANDLE hToken = nullptr;
                    if (WTSQueryUserToken(sessions[i].SessionId, &hToken)) {
                        std::string sid = SidFromToken(hToken);
                        CloseHandle(hToken);
                        if (!sid.empty()) {
                            WTSFreeMemory(sessions);
                            return sid;
                        }
                    }
                }
            }
            WTSFreeMemory(sessions);
        }
        // 3) resolve DOMAIN\USER to SID
        if (sessionId != 0xFFFFFFFF) {
            LPTSTR pUser = nullptr, pDomain = nullptr;
            DWORD bytes = 0;
            if (WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSUserName, &pUser, &bytes) && pUser && *pUser) {
                DWORD bytes2 = 0;
                if (WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSDomainName, &pDomain, &bytes2) && pDomain && *pDomain) {
                    std::string user = pUser;
                    std::string domain = pDomain;
                    WTSFreeMemory(pUser);
                    WTSFreeMemory(pDomain);

                    BYTE sidBuf[SECURITY_MAX_SID_SIZE];
                    DWORD sidSize = sizeof(sidBuf);
                    SID_NAME_USE use;
                    DWORD cchRefDomain = 0;
                    LookupAccountNameA(domain.c_str(), user.c_str(), sidBuf, &sidSize, nullptr, &cchRefDomain, &use);
                    std::string refDomain; refDomain.resize(cchRefDomain);
                    if (LookupAccountNameA(domain.c_str(), user.c_str(), sidBuf, &sidSize, &refDomain[0], &cchRefDomain, &use)) {
                        return SidToString((PSID)sidBuf);
                    }
                    return {};
                }
                if (pDomain) WTSFreeMemory(pDomain);
                WTSFreeMemory(pUser);
            }
        }
        return {};
    }

    static bool IsSystemSid(const std::string& sid) {
        return _stricmp(sid.c_str(), "S-1-5-18") == 0; // LocalSystem
    }

    static std::string getHardwareId() {
        // Fast path: current process token (works when not running as SYSTEM)
        {
            HANDLE hToken = nullptr;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
                std::string sid = SidFromToken(hToken);
                CloseHandle(hToken);
                if (!sid.empty() && !IsSystemSid(sid)) {
                    return sid; // real user SID
                }
            }
        }
        // If we're SYSTEM or couldn't read, try the active interactive user
        {
            std::string sid = SidFromActiveSessionToken();
            if (!sid.empty()) return sid;
        }
        // Last resort: return whatever our token is (could be SYSTEM), else default
        {
            HANDLE hToken = nullptr;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
                std::string sid = SidFromToken(hToken);
                CloseHandle(hToken);
                if (!sid.empty()) return sid;
            }
        }
        return "default-hwid";
    }

    static bool http_post_json_winhttp(const std::string& host,
        const std::string& path,
        const std::string& jsonBody,
        std::string& outBody)
    {
        bool ok = false;
        HINTERNET hSession = WinHttpOpen(L"BrutalAuth/2.0", // Updated to 2.0
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return false;

        std::wstring whost = to_wide(host);
        HINTERNET hConnect = WinHttpConnect(hSession, whost.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (hConnect) {
            std::wstring wpath = to_wide(path);
            HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wpath.c_str(),
                nullptr, WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES,
                WINHTTP_FLAG_SECURE);
            if (hRequest) {
                std::wstring headers = L"Content-Type: application/json\r\n";
                BOOL sent = WinHttpSendRequest(hRequest,
                    headers.c_str(), (DWORD)headers.size(),
                    (void*)jsonBody.data(), (DWORD)jsonBody.size(), // Use void* for direct data
                    (DWORD)jsonBody.size(), 0);
                if (sent) {
                    if (WinHttpReceiveResponse(hRequest, nullptr)) {
                        DWORD dwSize = 0;
                        do {
                            if (!WinHttpQueryDataAvailable(hRequest, &dwSize) || dwSize == 0) break;
                            std::string chunk;
                            chunk.resize(dwSize);
                            DWORD dwRead = 0;
                            if (!WinHttpReadData(hRequest, &chunk[0], dwSize, &dwRead) || dwRead == 0) break;
                            chunk.resize(dwRead);
                            outBody.append(chunk);
                        } while (dwSize > 0);
                        ok = true;
                    }
                }
                WinHttpCloseHandle(hRequest);
            }
            WinHttpCloseHandle(hConnect);
        }
        WinHttpCloseHandle(hSession);
        return ok;
    }

#elif __linux__

    static size_t curl_write_cb(void* ptr, size_t size, size_t nmemb, void* userdata) {
        size_t total = size * nmemb;
        std::string* out = reinterpret_cast<std::string*>(userdata);
        out->append(reinterpret_cast<const char*>(ptr), total);
        return total;
    }

    static bool http_post_json_curl(const std::string& url,
        const std::string& jsonBody,
        std::string& outBody)
    {
        CURL* curl = curl_easy_init();
        if (!curl) return false;

        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonBody.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)jsonBody.size());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &outBody);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "BrutalAuth/2.0");

        CURLcode res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return (res == CURLE_OK);
    }

    static std::string getHardwareId() {
        std::ifstream f("/etc/machine-id");
        std::string id;
        if (f && std::getline(f, id)) return id;
        return "default-hwid";
    }
#else
    static std::string getHardwareId() { return "default-hwid"; }
#endif

} // namespace

// -------------------- BrutalAuth methods (all out-of-class) --------------------

BrutalAuth::BrutalAuth(std::string applicationId, std::string host, std::string version)
    : applicationId_(std::move(applicationId)), host_(std::move(host)), version_(std::move(version)) {
}

bool BrutalAuth::contains_success_true(const std::string& body) {
    const auto p = body.find("\"success\":");
    if (p == std::string::npos) return false;
    const auto t = body.find("true", p);
    const auto f = body.find("false", p);
    return t != std::string::npos && (f == std::string::npos || t < f);
}

std::string BrutalAuth::makeJsonRegister(const std::string& licenseKey,
    const std::string& username,
    const std::string& password,
    const std::string& hwid,
    const std::string& applicationId)
{
    std::ostringstream o;
    o << "{"
        << "\"licenseKey\":\"" << licenseKey << "\","
        << "\"username\":\"" << username << "\","
        << "\"password\":\"" << password << "\","
        << "\"hwid\":\"" << hwid << "\","
        << "\"applicationId\":\"" << applicationId << "\""
        << "}";
    return o.str();
}

std::string BrutalAuth::makeJsonLogin(const std::string& username,
    const std::string& password,
    const std::string& hwid,
    const std::string& applicationId,
    const std::string& version)
{
    std::ostringstream o;
    o << "{"
        << "\"username\":\"" << username << "\","
        << "\"password\":\"" << password << "\","
        << "\"hwid\":\"" << hwid << "\","
        << "\"applicationId\":\"" << applicationId << "\","
        << "\"version\":\"" << version << "\""
        << "}";
    return o.str();
}

bool BrutalAuth::postJson(const std::string& pathOrUrl,
    const std::string& body,
    std::string& out)
{
#ifdef _WIN32
    return http_post_json_winhttp(host_, pathOrUrl, body, out);
#elif __linux__
    return http_post_json_curl("https://" + host_ + pathOrUrl, body, out);
#else
    (void)pathOrUrl; (void)body; (void)out;
    return false;
#endif
}
static std::string extract_error_message(const std::string& body)
{
    const std::string key = "\"error\"";
    auto keyPos = body.find(key);
    if (keyPos == std::string::npos)
        return "Unknown error";

    auto colon = body.find(':', keyPos);
    if (colon == std::string::npos)
        return "Unknown error";

    auto firstQuote = body.find('"', colon + 1);
    if (firstQuote == std::string::npos)
        return "Unknown error";

    auto secondQuote = body.find('"', firstQuote + 1);
    if (secondQuote == std::string::npos)
        return "Unknown error";

    return body.substr(firstQuote + 1, secondQuote - firstQuote - 1);
}

bool BrutalAuth::registerUser(const std::string& licenseKey,
    const std::string& username,
    const std::string& password)
{
    const std::string hwid = getHardwareId();
    const std::string payload =
        makeJsonRegister(licenseKey, username, password, hwid, applicationId_);

    std::string response;
    const bool ok = postJson("/register-user", payload, response);

    if (!ok) {
        std::cerr << "[BRUTAL AUTH] HTTP error during register.\n";
        return false;
    }

    if (contains_success_true(response)) {
        std::cout << "[BRUTAL AUTH] Registration successful!\n";
        return true;
    }

    std::cerr << "[BRUTAL AUTH] Registration failed: "
        << extract_error_message(response) << "\n";

    return false;
}


bool BrutalAuth::loginUser(const std::string& username,
    const std::string& password)
{
    const std::string hwid = getHardwareId();
    const std::string payload =
        makeJsonLogin(username, password, hwid, applicationId_, version_);

    std::string response;
    const bool ok = postJson("/login-user", payload, response);

    if (!ok) {
        std::cerr << "[BRUTAL AUTH] HTTP error during login.\n";
        return false;
    }

    if (contains_success_true(response)) {
        std::cout << "[BRUTAL AUTH] Login successful!\n";
        return true;
    }

    std::cerr << "[BRUTAL AUTH] Login failed: "
        << extract_error_message(response) << "\n";

    return false;
}
