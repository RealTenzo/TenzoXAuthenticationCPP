#pragma once

#include <windows.h>
#include <wininet.h>
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
#include <ctime>
#include <algorithm>
#include <random>
#include <sddl.h>
#pragma comment(lib, "wininet.lib")
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
        std::string AppName;
        std::string Secret;
        std::string Version;
        std::string ApiHost = "tenxoxauthentication.qzz.io";

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

        struct ApiResponse {
            bool Success;
            std::string Message;
            std::map<std::string, std::string> Data;
        };

        std::string GetHWID() {
            HANDLE hToken = nullptr;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
                return "HWID_FAIL";

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


        std::string HttpRequest(const std::string& endpoint, const std::string& jsonData) {
            HINTERNET hInternet = InternetOpenA(
                "TXA",
                INTERNET_OPEN_TYPE_DIRECT,
                NULL,
                NULL,
                0
            );
            if (!hInternet) return "";

            HINTERNET hConnect = InternetConnectA(
                hInternet,
                ApiHost.c_str(),
                INTERNET_DEFAULT_HTTPS_PORT,
                NULL,
                NULL,
                INTERNET_SERVICE_HTTP,
                0,
                0
            );
            if (!hConnect) {
                InternetCloseHandle(hInternet);
                return "";
            }

            std::string path = "/" + endpoint;

            HINTERNET hRequest = HttpOpenRequestA(
                hConnect,
                "POST",
                path.c_str(),
                NULL,
                NULL,
                NULL,
                INTERNET_FLAG_SECURE |
                INTERNET_FLAG_RELOAD |
                INTERNET_FLAG_NO_CACHE_WRITE,
                0
            );
            if (!hRequest) {
                InternetCloseHandle(hConnect);
                InternetCloseHandle(hInternet);
                return "";
            }

            std::string headers =
                "Content-Type: application/json\r\n"
                "Accept: application/json\r\n";

            BOOL sent = HttpSendRequestA(
                hRequest,
                headers.c_str(),
                (DWORD)headers.length(),
                (LPVOID)jsonData.c_str(),
                (DWORD)jsonData.length()
            );

            std::string response;
            if (sent) {
                char buffer[4096];
                DWORD bytesRead;
                while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead) {
                    buffer[bytesRead] = 0;
                    response += buffer;
                }
            }

            InternetCloseHandle(hRequest);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);

            return response;
        }

        ApiResponse ParseResponse(const std::string& jsonStr) {
            ApiResponse result{ false, "", {} };

            // success
            if (jsonStr.find("\"success\":true") != std::string::npos)
                result.Success = true;

            // message
            size_t msgPos = jsonStr.find("\"message\"");
            if (msgPos != std::string::npos) {
                size_t start = jsonStr.find("\"", msgPos + 9) + 1;
                size_t end = jsonStr.find("\"", start);
                result.Message = jsonStr.substr(start, end - start);
            }

            // serverVersion (IMPORTANT FIX)
            size_t verPos = jsonStr.find("\"serverVersion\"");
            if (verPos != std::string::npos) {
                size_t start = jsonStr.find("\"", verPos + 15) + 1;
                size_t end = jsonStr.find("\"", start);
                result.Data["serverVersion"] = jsonStr.substr(start, end - start);
            }

            // username
            size_t userPos = jsonStr.find("\"username\"");
            if (userPos != std::string::npos) {
                size_t start = jsonStr.find("\"", userPos + 10) + 1;
                size_t end = jsonStr.find("\"", start);
                result.Data["username"] = jsonStr.substr(start, end - start);
            }

            // subscription
            size_t subPos = jsonStr.find("\"subscription\"");
            if (subPos != std::string::npos) {
                size_t start = jsonStr.find("\"", subPos + 14) + 1;
                size_t end = jsonStr.find("\"", start);
                result.Data["subscription"] = jsonStr.substr(start, end - start);
            }

            // expiry
            size_t expPos = jsonStr.find("\"expiry\"");
            if (expPos != std::string::npos) {
                size_t start = jsonStr.find("\"", expPos + 8) + 1;
                size_t end = jsonStr.find("\"", start);
                result.Data["expiry"] = jsonStr.substr(start, end - start);
            }
            // variable
            size_t varsPos = jsonStr.find("\"variables\"");
            if (varsPos != std::string::npos) {
                size_t start = jsonStr.find("{", varsPos);
                size_t end = jsonStr.find("}", start);

                if (start != std::string::npos && end != std::string::npos) {
                    std::string varsBlock = jsonStr.substr(start + 1, end - start - 1);

                    size_t pos = 0;
                    while ((pos = varsBlock.find("\"", pos)) != std::string::npos) {
                        size_t keyEnd = varsBlock.find("\"", pos + 1);
                        std::string key = varsBlock.substr(pos + 1, keyEnd - pos - 1);

                        size_t valStart = varsBlock.find("\"", keyEnd + 1);
                        size_t valEnd = varsBlock.find("\"", valStart + 1);
                        std::string value = varsBlock.substr(valStart + 1, valEnd - valStart - 1);

                        result.Data[key] = value;
                        pos = valEnd + 1;
                    }
                }
            }
            return result;
        }


        void ShowError(const std::string& title, const std::string& message) {
            AllocConsole();
            HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

            SetConsoleTextAttribute(hConsole, 12);
            std::cout << "\n?" << std::string(70, '=') << "?\n";
            std::cout << "? " << std::left << std::setw(69) << title << " ?\n";
            std::cout << "?" << std::string(70, '=') << "?\n";

            std::istringstream iss(message);
            std::string line;
            while (std::getline(iss, line)) {
                std::cout << "? " << std::left << std::setw(69) << line << " ?\n";
            }

            std::cout << "?" << std::string(70, '=') << "?\n";
            SetConsoleTextAttribute(hConsole, 7);
            std::cout << "\nPress any key to exit...";
            std::cin.get();

            FreeConsole();
        }

        bool CheckIfPaused() {
            std::string json = "{\"secret\":\"" + Secret + "\",\"appName\":\"" + AppName + "\"}";
            std::string response = HttpRequest("isapplicationpaused", json);
            ApiResponse result = ParseResponse(response);
            return result.Success && result.Message == "APPLICATION_PAUSED";
        }

        std::pair<bool, std::string> CheckVersion() {
            std::string json = "{\"secret\":\"" + Secret + "\",\"appName\":\"" + AppName + "\",\"appVersion\":\"" + Version + "\"}";
            std::string response = HttpRequest("versioncheck", json);
            ApiResponse result = ParseResponse(response);

            if (result.Success) {
                if (result.Message == "VERSION_OK") {
                    return { true, Version };
                }
                else if (result.Message == "VERSION_MISMATCH") {
                    auto it = result.Data.find("serverVersion");
                    if (it != result.Data.end()) {
                        return { false, it->second };
                    }
                    return { false, "Unknown" };
                }
            }
            return { false, "Unknown" };
        }

        bool LoadAppVariables() {
            std::string json = "{\"secret\":\"" + Secret + "\",\"appName\":\"" + AppName + "\"}";
            std::string response = HttpRequest("getvariables", json);
            ApiResponse result = ParseResponse(response);

            if (result.Success && result.Message != "NO_VARIABLES") {
                std::lock_guard<std::mutex> lock(varMutex);
                Variables.clear();

                for (const auto& pair : result.Data) {
                    Variables[pair.first] = pair.second;
                }
                return true;
            }
            return false;
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

                    std::lock_guard<std::mutex> lock(responseMutex);
                    ResponseMessage = "TXA SDK Initialized successfully!";
                }
                catch (...) {
                    ShowError("Init Error", "Initialization failed");
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
                ResponseMessage = "Error: Call TXA.Init() first";
                result.Message = ResponseMessage;
                return result;
            }

            try {
                std::string hwid = GetHWID();
                std::string json = "{\"username\":\"" + username +
                    "\",\"password\":\"" + password +
                    "\",\"secret\":\"" + Secret +
                    "\",\"appName\":\"" + AppName +
                    "\",\"appVersion\":\"" + Version +
                    "\",\"hwid\":\"" + hwid + "\"}";

                std::string response = HttpRequest("login", json);
                ApiResponse apiResp = ParseResponse(response);

                if (apiResp.Success) {
                    IsLoggedIn = true;

                    CurrentUser.Username = apiResp.Data.count("username") ? apiResp.Data["username"] : "";
                    CurrentUser.Subscription = apiResp.Data.count("subscription") ? apiResp.Data["subscription"] : "";
                    CurrentUser.Expiry = apiResp.Data.count("expiry") ? apiResp.Data["expiry"] : "";

                    ResponseMessage = "Login successful! Welcome, " + CurrentUser.Username;

                    result.Success = true;
                    result.Message = ResponseMessage;
                    result.User = CurrentUser;
                    return result;
                }
                else {
                    std::string error = apiResp.Message;
                    std::string formatted;

                    if (error.find("INVALID_CREDENTIALS") != std::string::npos ||
                        error.find("Invalid username or password") != std::string::npos) {
                        formatted = "Invalid username or password";
                    }
                    else if (error.find("HWID_RESET") != std::string::npos ||
                        error.find("HWID_MISMATCH") != std::string::npos) {
                        formatted = "HWID mismatch. Please contact support to reset your HWID";
                    }
                    else if (error.find("BANNED") != std::string::npos ||
                        error.find("suspended") != std::string::npos) {
                        formatted = "Account has been banned or suspended";
                    }
                    else if (error.find("expired") != std::string::npos ||
                        error.find("EXPIRED") != std::string::npos) {
                        formatted = "Subscription has expired";
                    }
                    else if (error.find("MAX_DEVICES") != std::string::npos) {
                        formatted = "Maximum number of devices reached";
                    }
                    else {
                        formatted = "Login failed: " + error;
                    }

                    ResponseMessage = formatted;
                    result.Message = formatted;
                    return result;
                }
            }
            catch (...) {
                ResponseMessage = "Connection error";
                result.Message = ResponseMessage;
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
                ResponseMessage = "Error: Call TXA.Init() first";
                result.Message = ResponseMessage;
                return result;
            }

            try {
                std::string hwid = GetHWID();
                std::string json = "{\"username\":\"" + username +
                    "\",\"password\":\"" + password +
                    "\",\"licenseKey\":\"" + license +
                    "\",\"secret\":\"" + Secret +
                    "\",\"appName\":\"" + AppName +
                    "\",\"appVersion\":\"" + Version +
                    "\",\"hwid\":\"" + hwid + "\"}";

                std::string response = HttpRequest("register", json);
                ApiResponse apiResp = ParseResponse(response);

                if (apiResp.Success) {
                    ResponseMessage = "Registration successful! You can login now";
                    result.Success = true;
                    result.Message = ResponseMessage;
                    return result;
                }
                else {
                    std::string error = apiResp.Message;
                    std::string formatted;

                    if (error.find("INVALID_LICENSE") != std::string::npos) {
                        formatted = "Invalid license key";
                    }
                    else if (error.find("USERNAME_TAKEN") != std::string::npos) {
                        formatted = "Username is already taken";
                    }
                    else if (error.find("LICENSE_USED") != std::string::npos) {
                        formatted = "License key has already been used";
                    }
                    else if (error.find("LICENSE_EXPIRED") != std::string::npos) {
                        formatted = "License key has expired";
                    }
                    else if (error.find("WEAK_PASSWORD") != std::string::npos) {
                        formatted = "Password is too weak. Please use a stronger password";
                    }
                    else if (error.find("INVALID_USERNAME") != std::string::npos) {
                        formatted = "Invalid username format";
                    }
                    else {
                        formatted = "Registration failed: " + error;
                    }

                    ResponseMessage = formatted;
                    result.Message = formatted;
                    return result;
                }
            }
            catch (...) {
                ResponseMessage = "Connection error";
                result.Message = ResponseMessage;
                return result;
            }
        }

        std::string Var(const std::string& name) {
            std::lock_guard<std::mutex> lock(varMutex);
            auto it = Variables.find(name);
            if (it != Variables.end()) {
                return it->second;
            }
            return "VARIABLE_NOT_FOUND";
        }

        template<typename T>
        T Get(const std::string& name) {
            std::string value = Var(name);
            if (value == "VARIABLE_NOT_FOUND") return T();

            if constexpr (std::is_same_v<T, bool>) {
                std::string lower = value;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
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
                ResponseMessage = "Error: Call TXA.Init() first";
                return "";
            }

            std::string cached = Var(name);
            if (cached != "VARIABLE_NOT_FOUND") {
                ResponseMessage = "Variable '" + name + "' retrieved from cache";
                return cached;
            }

            try {
                std::string json = "{\"secret\":\"" + Secret +
                    "\",\"appName\":\"" + AppName +
                    "\",\"appVersion\":\"" + Version +
                    "\",\"varName\":\"" + name + "\"}";

                std::string response = HttpRequest("getvariable", json);
                ApiResponse apiResp = ParseResponse(response);

                if (apiResp.Success) {
                    auto it = apiResp.Data.find("value");
                    if (it != apiResp.Data.end()) {
                        std::lock_guard<std::mutex> lock(varMutex);
                        Variables[name] = it->second;
                        ResponseMessage = "Variable '" + name + "' retrieved successfully";
                        return it->second;
                    }
                    ResponseMessage = "Variable '" + name + "' not found";
                    return "";
                }
                else {
                    ResponseMessage = "Failed to get variable '" + name + "': " + apiResp.Message;
                    return "";
                }
            }
            catch (...) {
                ResponseMessage = "Connection error";
                return "";
            }
        }

        bool RefreshVariables() {
            if (!IsInitialized) {
                ResponseMessage = "Error: Call TXA.Init() first";
                return false;
            }

            try {
                bool result = LoadAppVariables();
                if (result) {
                    ResponseMessage = "Successfully refreshed " + std::to_string(Variables.size()) + " variables";
                    return true;
                }
                else {
                    ResponseMessage = "No variables found or failed to load";
                    return false;
                }
            }
            catch (...) {
                ResponseMessage = "Failed to refresh variables";
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