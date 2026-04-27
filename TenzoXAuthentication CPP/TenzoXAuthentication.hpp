#pragma once

#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <iphlpapi.h>
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <stdexcept>
#include <sddl.h>
#include "xorstr.hpp"

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace TXA {

    class UserData {
    public:
        std::string Username;
        std::string Subscription;
        std::string Expiry;
    };

    class Auth {
    private:
        struct ApiResponse {
            bool Success = false;
            std::string Message;
            std::string ServerVersion;
            std::string Username;
            std::string Subscription;
            std::string Expiry;
            std::string Value;
            std::map<std::string, std::string> Variables;
        };

        std::string AppName;
        std::string Secret;
        std::string Version;
        std::string ApiHost = "tenxoxauthentication.qzz.io";
        std::string PinnedCertSha256 = "DB:42:42:C4:90:3E:47:7D:F2:76:29:33:7C:68:EA:BA:B5:31:28:CA:2B:C4:EB:48:2B:40:79:00:C9:4D:95:ED";

        std::atomic<bool> IsInitialized{ false };
        std::atomic<bool> IsLoggedIn{ false };
        std::atomic<bool> IsApplicationActive{ false };
        std::atomic<bool> IsVersionCorrect{ false };

        std::string ResponseMessage;
        std::string ServerVersion;
        UserData CurrentUser;
        std::map<std::string, std::string> Variables;

        std::mutex varMutex;
        std::mutex responseMutex;

        static std::string TamperDetectedMessage() {
            return _xor_("Tamper detected. Access blocked.").str();
        }

        static std::wstring Utf8ToWide(const std::string& value) {
            if (value.empty()) {
                return std::wstring();
            }

            int needed = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
            if (needed <= 0) {
                throw std::runtime_error("Failed to convert string");
            }

            std::wstring result(static_cast<std::size_t>(needed) - 1, L'\0');
            if (MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, result.data(), needed) <= 0) {
                throw std::runtime_error("Failed to convert string");
            }

            return result;
        }

        void SetResponseMessage(const std::string& message) {
            std::lock_guard<std::mutex> lock(responseMutex);
            ResponseMessage = message;
        }

        static std::string JsonEscape(const std::string& input) {
            std::ostringstream out;
            for (unsigned char c : input) {
                switch (c) {
                case '\\': out << "\\\\"; break;
                case '"': out << "\\\""; break;
                case '\b': out << "\\b"; break;
                case '\f': out << "\\f"; break;
                case '\n': out << "\\n"; break;
                case '\r': out << "\\r"; break;
                case '\t': out << "\\t"; break;
                default:
                    if (c < 0x20) {
                        out << "\\u"
                            << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
                            << static_cast<int>(c)
                            << std::dec << std::nouppercase;
                    }
                    else {
                        out << static_cast<char>(c);
                    }
                }
            }
            return out.str();
        }

        static std::string ExtractJsonString(const std::string& json, const std::string& key) {
            std::string token = "\"" + key + "\"";
            std::size_t keyPos = json.find(token);
            if (keyPos == std::string::npos) {
                return "";
            }

            std::size_t colonPos = json.find(':', keyPos + token.length());
            if (colonPos == std::string::npos) {
                return "";
            }

            std::size_t firstQuote = json.find('"', colonPos + 1);
            if (firstQuote == std::string::npos) {
                return "";
            }

            std::string value;
            bool escaped = false;
            for (std::size_t i = firstQuote + 1; i < json.size(); ++i) {
                char ch = json[i];
                if (escaped) {
                    switch (ch) {
                    case '"': value.push_back('"'); break;
                    case '\\': value.push_back('\\'); break;
                    case '/': value.push_back('/'); break;
                    case 'b': value.push_back('\b'); break;
                    case 'f': value.push_back('\f'); break;
                    case 'n': value.push_back('\n'); break;
                    case 'r': value.push_back('\r'); break;
                    case 't': value.push_back('\t'); break;
                    default: value.push_back(ch); break;
                    }
                    escaped = false;
                    continue;
                }

                if (ch == '\\') {
                    escaped = true;
                    continue;
                }

                if (ch == '"') {
                    return value;
                }

                value.push_back(ch);
            }

            return "";
        }

        static bool ExtractJsonBool(const std::string& json, const std::string& key, bool defaultValue = false) {
            std::string token = "\"" + key + "\"";
            std::size_t keyPos = json.find(token);
            if (keyPos == std::string::npos) {
                return defaultValue;
            }

            std::size_t colonPos = json.find(':', keyPos + token.length());
            if (colonPos == std::string::npos) {
                return defaultValue;
            }

            std::size_t valuePos = json.find_first_not_of(" \t\r\n", colonPos + 1);
            if (valuePos == std::string::npos) {
                return defaultValue;
            }

            if (json.compare(valuePos, 4, "true") == 0) {
                return true;
            }

            if (json.compare(valuePos, 5, "false") == 0) {
                return false;
            }

            return defaultValue;
        }

        static std::string ExtractRawJsonObject(const std::string& json, const std::string& key) {
            std::string token = "\"" + key + "\"";
            std::size_t keyPos = json.find(token);
            if (keyPos == std::string::npos) {
                return "";
            }

            std::size_t colonPos = json.find(':', keyPos + token.length());
            if (colonPos == std::string::npos) {
                return "";
            }

            std::size_t start = json.find('{', colonPos + 1);
            if (start == std::string::npos) {
                return "";
            }

            int depth = 0;
            bool inString = false;
            bool escaped = false;

            for (std::size_t i = start; i < json.size(); ++i) {
                char ch = json[i];
                if (inString) {
                    if (escaped) {
                        escaped = false;
                    }
                    else if (ch == '\\') {
                        escaped = true;
                    }
                    else if (ch == '"') {
                        inString = false;
                    }
                    continue;
                }

                if (ch == '"') {
                    inString = true;
                    continue;
                }

                if (ch == '{') {
                    ++depth;
                }
                else if (ch == '}') {
                    --depth;
                    if (depth == 0) {
                        return json.substr(start, i - start + 1);
                    }
                }
            }

            return "";
        }

        static std::map<std::string, std::string> ParseStringMap(const std::string& jsonObject) {
            std::map<std::string, std::string> values;
            if (jsonObject.empty()) {
                return values;
            }

            std::size_t pos = 0;
            while (true) {
                std::size_t keyStart = jsonObject.find('"', pos);
                if (keyStart == std::string::npos) {
                    break;
                }

                std::size_t keyEnd = jsonObject.find('"', keyStart + 1);
                if (keyEnd == std::string::npos) {
                    break;
                }

                std::string key = jsonObject.substr(keyStart + 1, keyEnd - keyStart - 1);
                std::size_t colonPos = jsonObject.find(':', keyEnd + 1);
                if (colonPos == std::string::npos) {
                    break;
                }

                std::size_t valueStart = jsonObject.find('"', colonPos + 1);
                if (valueStart == std::string::npos) {
                    break;
                }

                std::string value;
                bool escaped = false;
                for (std::size_t i = valueStart + 1; i < jsonObject.size(); ++i) {
                    char ch = jsonObject[i];
                    if (escaped) {
                        switch (ch) {
                        case '"': value.push_back('"'); break;
                        case '\\': value.push_back('\\'); break;
                        case 'n': value.push_back('\n'); break;
                        case 'r': value.push_back('\r'); break;
                        case 't': value.push_back('\t'); break;
                        default: value.push_back(ch); break;
                        }
                        escaped = false;
                        continue;
                    }

                    if (ch == '\\') {
                        escaped = true;
                        continue;
                    }

                    if (ch == '"') {
                        pos = i + 1;
                        values[key] = value;
                        break;
                    }

                    value.push_back(ch);
                }
            }

            return values;
        }

        static std::string BytesToFingerprint(const BYTE* bytes, DWORD length) {
            std::ostringstream out;
            out << std::uppercase << std::hex << std::setfill('0');
            for (DWORD i = 0; i < length; ++i) {
                if (i > 0) {
                    out << ":";
                }
                out << std::setw(2) << static_cast<int>(bytes[i]);
            }
            return out.str();
        }

        static std::string NormalizeFingerprint(std::string value) {
            value.erase(std::remove_if(value.begin(), value.end(), [](unsigned char c) {
                return std::isspace(c) != 0;
            }), value.end());

            std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
                return static_cast<char>(std::toupper(c));
            });

            return value;
        }

        std::string GetHWID() {
            HANDLE hToken = nullptr;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
                return "HWID_FAIL";
            }

            DWORD size = 0;
            GetTokenInformation(hToken, TokenUser, nullptr, 0, &size);

            std::vector<BYTE> buffer(size);
            if (!GetTokenInformation(hToken, TokenUser, buffer.data(), size, &size)) {
                CloseHandle(hToken);
                return "HWID_FAIL";
            }

            TOKEN_USER* tokenUser = reinterpret_cast<TOKEN_USER*>(buffer.data());

            LPSTR sidString = nullptr;
            if (!ConvertSidToStringSidA(tokenUser->User.Sid, &sidString)) {
                CloseHandle(hToken);
                return "HWID_FAIL";
            }

            std::string sid = sidString;

            LocalFree(sidString);
            CloseHandle(hToken);
            return sid;
        }

        std::string BuildRequestJson(const std::map<std::string, std::string>& fields) const {
            std::ostringstream json;
            json << "{";

            bool first = true;
            for (const auto& [key, value] : fields) {
                if (!first) {
                    json << ",";
                }
                first = false;
                json << "\"" << JsonEscape(key) << "\":\"" << JsonEscape(value) << "\"";
            }

            json << "}";
            return json.str();
        }

        ApiResponse ParseResponse(const std::string& jsonStr) {
            ApiResponse result;
            result.Success = ExtractJsonBool(jsonStr, "success", false);
            result.Message = ExtractJsonString(jsonStr, "message");
            result.ServerVersion = ExtractJsonString(jsonStr, "serverVersion");
            result.Username = ExtractJsonString(jsonStr, "username");
            result.Subscription = ExtractJsonString(jsonStr, "subscription");
            result.Expiry = ExtractJsonString(jsonStr, "expiry");
            result.Value = ExtractJsonString(jsonStr, "value");
            result.Variables = ParseStringMap(ExtractRawJsonObject(jsonStr, "variables"));
            return result;
        }
        void VerifyPinnedCertificate(HINTERNET hRequest) const {
            PCCERT_CONTEXT certContext = nullptr;
            DWORD certContextSize = sizeof(certContext);

            if (!WinHttpQueryOption(hRequest, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &certContext, &certContextSize) || !certContext) {
                throw std::runtime_error(TamperDetectedMessage());
            }

            BYTE hash[32] = {};
            DWORD hashSize = sizeof(hash);
            bool hashOk = CertGetCertificateContextProperty(certContext, CERT_SHA256_HASH_PROP_ID, hash, &hashSize) == TRUE;
            CertFreeCertificateContext(certContext);

            if (!hashOk || hashSize == 0) {
                throw std::runtime_error(TamperDetectedMessage());
            }

            std::string actual = NormalizeFingerprint(BytesToFingerprint(hash, hashSize));
            std::string pinned = NormalizeFingerprint(PinnedCertSha256);
            if (actual != pinned) {
                throw std::runtime_error(TamperDetectedMessage());
            }
        }

        std::string HttpRequest(const std::string& endpoint, const std::string& jsonBody) {
            HINTERNET hSession = WinHttpOpen(L"TXA/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
            if (!hSession) {
                return "";
            }

            DWORD timeoutMs = 15000;
            WinHttpSetTimeouts(hSession, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

            std::wstring host = Utf8ToWide(ApiHost);
            HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
            if (!hConnect) {
                WinHttpCloseHandle(hSession);
                return "";
            }

            std::wstring path = Utf8ToWide("/" + endpoint);
            HINTERNET hRequest = WinHttpOpenRequest(
                hConnect,
                L"POST",
                path.c_str(),
                nullptr,
                WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES,
                WINHTTP_FLAG_SECURE);

            if (!hRequest) {
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                return "";
            }

            static const wchar_t* headers = L"Content-Type: application/json\r\nAccept: application/json\r\n";
            BOOL sent = WinHttpSendRequest(
                hRequest,
                headers,
                -1L,
                reinterpret_cast<LPVOID>(const_cast<char*>(jsonBody.data())),
                static_cast<DWORD>(jsonBody.size()),
                static_cast<DWORD>(jsonBody.size()),
                0);

            if (!sent || !WinHttpReceiveResponse(hRequest, nullptr)) {
                WinHttpCloseHandle(hRequest);
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                return "";
            }

            VerifyPinnedCertificate(hRequest);

            std::string response;
            DWORD available = 0;
            do {
                available = 0;
                if (!WinHttpQueryDataAvailable(hRequest, &available)) {
                    response.clear();
                    break;
                }

                if (available == 0) {
                    break;
                }

                std::vector<char> buffer(static_cast<std::size_t>(available) + 1, '\0');
                DWORD bytesRead = 0;
                if (!WinHttpReadData(hRequest, buffer.data(), available, &bytesRead)) {
                    response.clear();
                    break;
                }

                response.append(buffer.data(), bytesRead);
            } while (available > 0);

            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);

            return response;
        }

        ApiResponse PerformRequest(const std::string& endpoint, const std::map<std::string, std::string>& fields) {
            std::string rawResponse = HttpRequest(endpoint, BuildRequestJson(fields));
            if (rawResponse.empty()) {
                throw std::runtime_error("Network error");
            }
            return ParseResponse(rawResponse);
        }

        void ShowError(const std::string& title, const std::string& message) {
            AllocConsole();
            HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

            SetConsoleTextAttribute(hConsole, 12);
            std::cout << "\n[" << std::string(70, '=') << "]\n";
            std::cout << "[ " << std::left << std::setw(69) << title << " ]\n";
            std::cout << "[" << std::string(70, '=') << "]\n";

            std::istringstream iss(message);
            std::string line;
            while (std::getline(iss, line)) {
                std::cout << "[ " << std::left << std::setw(69) << line << " ]\n";
            }

            std::cout << "[" << std::string(70, '=') << "]\n";
            SetConsoleTextAttribute(hConsole, 7);
            std::cout << "\nPress any key to exit...";
            std::cin.get();

            FreeConsole();
        }

        bool CheckIfPaused() {
            ApiResponse result = PerformRequest("isapplicationpaused", {
                {"secret", Secret},
                {"appName", AppName}
                });
            return result.Success && result.Message == "APPLICATION_PAUSED";
        }

        std::pair<bool, std::string> CheckVersion() {
            ApiResponse result = PerformRequest("versioncheck", {
                {"secret", Secret},
                {"appName", AppName},
                {"appVersion", Version}
                });
            if (result.Success && result.Message == "VERSION_OK") {
                return { true, Version };
            }

            if (result.Message == "VERSION_MISMATCH" && !result.ServerVersion.empty()) {
                return { false, result.ServerVersion };
            }

            return { false, "Unknown" };
        }

        bool LoadAppVariables() {
            ApiResponse result = PerformRequest("getvariables", {
                {"secret", Secret},
                {"appName", AppName}
                });
            if (!result.Success || result.Message == "NO_VARIABLES") {
                return false;
            }

            std::lock_guard<std::mutex> lock(varMutex);
            Variables = result.Variables;
            return true;
        }

    public:
        Auth(const std::string& name, const std::string& secret, const std::string& version)
            : AppName(name), Secret(secret), Version(version) {
        }

        void Init() {
            if (AppName.empty() || Secret.empty() || Version.empty()) {
                ShowError("TXA Auth Error", "AppName/Secret/Version missing");
                ExitProcess(0);
            }

            std::thread([this]() {
                try {
                    bool paused = CheckIfPaused();
                    if (paused) {
                        ShowError("Application Paused", "Application is currently paused by administrator");
                        ExitProcess(0);
                    }
                    IsApplicationActive = !paused;

                    auto versionCheck = CheckVersion();
                    IsVersionCorrect = versionCheck.first;
                    ServerVersion = versionCheck.second;

                    if (!IsVersionCorrect) {
                        ShowError("Update Required",
                            "Version mismatch!\n\nYour version: " + Version +
                            "\nServer version: " + ServerVersion +
                            "\n\nPlease update to the latest version.");
                        ExitProcess(0);
                    }

                    LoadAppVariables();
                    IsInitialized = true;
                    SetResponseMessage("TXA SDK initialized successfully.");
                }
                catch (const std::exception& ex) {
                    ShowError("Initialization Failed", ex.what());
                    ExitProcess(0);
                }
                catch (...) {
                    ShowError("Initialization Failed", "Initialization failed");
                    ExitProcess(0);
                }
                }).detach();
        }

        struct LoginResult {
            bool Success;
            std::string Message;
            UserData User;
        };

        LoginResult Login(const std::string& username, const std::string& password) {
            LoginResult result{ false, "", {} };

            if (!IsInitialized) {
                SetResponseMessage("Error: Call TXA.Init() first");
                result.Message = Response();
                return result;
            }

            try {
                ApiResponse apiResp = PerformRequest("login", {
                    {"username", username},
                    {"password", password},
                    {"secret", Secret},
                    {"appName", AppName},
                    {"appVersion", Version},
                    {"hwid", GetHWID()}
                    });
                if (!apiResp.Success) {
                    SetResponseMessage(apiResp.Message.empty() ? "Login failed" : apiResp.Message);
                    result.Message = Response();
                    return result;
                }

                IsLoggedIn = true;
                CurrentUser.Username = apiResp.Username;
                CurrentUser.Subscription = apiResp.Subscription;
                CurrentUser.Expiry = apiResp.Expiry;

                SetResponseMessage("Login successful! Welcome, " + CurrentUser.Username);
                result.Success = true;
                result.Message = Response();
                result.User = CurrentUser;
                return result;
            }
            catch (const std::exception& ex) {
                SetResponseMessage(ex.what());
                result.Message = Response();
                return result;
            }
            catch (...) {
                SetResponseMessage("Connection error");
                result.Message = Response();
                return result;
            }
        }

        struct RegisterResult {
            bool Success;
            std::string Message;
        };

        RegisterResult Register(const std::string& username, const std::string& password, const std::string& license) {
            RegisterResult result{ false, "" };

            if (!IsInitialized) {
                SetResponseMessage("Error: Call TXA.Init() first");
                result.Message = Response();
                return result;
            }

            try {
                ApiResponse apiResp = PerformRequest("register", {
                    {"username", username},
                    {"password", password},
                    {"licenseKey", license},
                    {"secret", Secret},
                    {"appName", AppName},
                    {"appVersion", Version},
                    {"hwid", GetHWID()}
                    });
                if (!apiResp.Success) {
                    SetResponseMessage(apiResp.Message.empty() ? "Registration failed" : apiResp.Message);
                    result.Message = Response();
                    return result;
                }

                SetResponseMessage("Registration successful! You can login now.");
                result.Success = true;
                result.Message = Response();
                return result;
            }
            catch (const std::exception& ex) {
                SetResponseMessage(ex.what());
                result.Message = Response();
                return result;
            }
            catch (...) {
                SetResponseMessage("Connection error");
                result.Message = Response();
                return result;
            }
        }

        std::string Var(const std::string& name) {
            std::lock_guard<std::mutex> lock(varMutex);
            auto it = Variables.find(name);
            return it != Variables.end() ? it->second : "VARIABLE_NOT_FOUND";
        }

        template<typename T>
        T Get(const std::string& name) {
            std::string value = Var(name);
            if (value == "VARIABLE_NOT_FOUND") {
                return T();
            }

            if constexpr (std::is_same_v<T, bool>) {
                std::string lower = value;
                std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                    });
                return lower == "true" || lower == "1";
            }
            else if constexpr (std::is_same_v<T, int>) {
                return std::stoi(value);
            }
            else if constexpr (std::is_same_v<T, float>) {
                return std::stof(value);
            }
            else if constexpr (std::is_same_v<T, double>) {
                return std::stod(value);
            }
            else {
                return T(value);
            }
        }

        std::string GetVariable(const std::string& name) {
            if (!IsInitialized) {
                SetResponseMessage("Error: Call TXA.Init() first");
                return "";
            }

            std::string cached = Var(name);
            if (cached != "VARIABLE_NOT_FOUND") {
                SetResponseMessage("Variable '" + name + "' retrieved from cache");
                return cached;
            }

            try {
                ApiResponse apiResp = PerformRequest("getvariable", {
                    {"secret", Secret},
                    {"appName", AppName},
                    {"appVersion", Version},
                    {"varName", name}
                    });
                if (!apiResp.Success) {
                    SetResponseMessage("Failed to get variable '" + name + "': " + apiResp.Message);
                    return "";
                }

                if (apiResp.Value.empty()) {
                    SetResponseMessage("Variable '" + name + "' not found");
                    return "";
                }

                {
                    std::lock_guard<std::mutex> lock(varMutex);
                    Variables[name] = apiResp.Value;
                }

                SetResponseMessage("Variable '" + name + "' retrieved successfully");
                return apiResp.Value;
            }
            catch (const std::exception& ex) {
                SetResponseMessage(ex.what());
                return "";
            }
            catch (...) {
                SetResponseMessage("Connection error");
                return "";
            }
        }

        bool RefreshVariables() {
            if (!IsInitialized) {
                SetResponseMessage("Error: Call TXA.Init() first");
                return false;
            }

            try {
                if (!LoadAppVariables()) {
                    SetResponseMessage("No variables found or failed to load");
                    return false;
                }

                SetResponseMessage("Successfully refreshed " + std::to_string(Variables.size()) + " variables");
                return true;
            }
            catch (const std::exception& ex) {
                SetResponseMessage(ex.what());
                return false;
            }
            catch (...) {
                SetResponseMessage("Failed to refresh variables");
                return false;
            }
        }

        std::string Response() {
            std::lock_guard<std::mutex> lock(responseMutex);
            return ResponseMessage;
        }

        std::string operator[](const std::string& name) {
            return Var(name);
        }

        UserData User() { return CurrentUser; }
        bool Initialized() { return IsInitialized; }
        bool LoggedIn() { return IsLoggedIn; }
        bool Active() { return IsApplicationActive; }

        bool VersionOk() { return IsVersionCorrect; }
        std::string ServerVer() { return ServerVersion; }
    };
}
