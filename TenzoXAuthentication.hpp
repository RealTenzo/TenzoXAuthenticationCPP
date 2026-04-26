#pragma once

#include <windows.h>
#include <wininet.h>
#include <wincrypt.h>
#include <bcrypt.h>
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
#include <cctype>
#include <cstdlib>
#include <stdexcept>
#include <fstream>
#include <sddl.h>
#include "xorstr.hpp"

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "iphlpapi.lib")

#ifndef TXA_RESPONSE_SIGNING_PUBLIC_KEY_PEM
#define TXA_RESPONSE_SIGNING_PUBLIC_KEY_PEM R"(-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAh3fjJEqt8/GbGNkhn9ws
8v7cStTdgEv2712vsJUhyJXS/hhG6wLcTHCk/hY/+jICvAF7lsSAMmz4Nwntp62B
cPj+OP6eWcX4WSSciK0O+i1qiF0QxXEFchvQCcUa3GVxrDLKFPB5/44ct+INqUV5
dZZYhZl39zQcs+2zvY3kJGvOafopGhsuedMh7eLkPP09lUAXnX30yOyU4G71MXut
mKo1V8M3F4O7G91s6bZLhxONOU6NhgSuykCM2u3hzP34nXC4uJe0Lx/8ENftWNwZ
3Qf3cuXcXCZJsWSzEhfYSZX5waQOUoE5qqqslygoCt40lCP7qk1Z9drP9C9losxy
f1vHTTismKkTnVHSZJRXu1wtYC79J8F3f8oG97uwo3p+p1LA+CdF1X69xSY0nFZu
QF1qxkOV4NUrcOXra+blw8FaowKahBBzjJeAzjoTa02DxexQSk2kDVvPmUrOv68U
L/i6HsvOzaC62R7mNOKiqaDB9bircvGj/BknhX5Etf5RAgMBAAE=
-----END PUBLIC KEY-----)"
#endif

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
            std::string RequestNonce;
            std::string ServerTimestamp;
            std::string Signature;
            std::map<std::string, std::string> Variables;
        };

        struct RequestContext {
            std::string Endpoint;
            std::string JsonBody;
            std::string Nonce;
            std::string Timestamp;
        };

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

        std::string ResponseSigningPublicKeyPem = TXA_RESPONSE_SIGNING_PUBLIC_KEY_PEM;
        long long AllowedClockSkewSeconds = 120;
        bool EnforceStrictSecurity = true;

        std::mutex varMutex;
        std::mutex responseMutex;

        static std::string TamperDetectedMessage() {
            return _xor_("Tamper detected. Access blocked.").str();
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

        static long long CurrentUnixTimeSeconds() {
            return static_cast<long long>(std::time(nullptr));
        }

        static std::string TrimCopy(std::string value) {
            auto notSpace = [](unsigned char c) { return !std::isspace(c); };
            value.erase(value.begin(), std::find_if(value.begin(), value.end(), notSpace));
            value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());
            return value;
        }

        static std::string GenerateRandomHex(std::size_t byteCount = 16) {
            std::vector<unsigned char> bytes(byteCount);
            if (BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
                throw std::runtime_error("Failed to generate secure random bytes");
            }

            static const char* hex = "0123456789ABCDEF";
            std::string output;
            output.reserve(byteCount * 2);

            for (unsigned char byte : bytes) {
                output.push_back(hex[(byte >> 4) & 0x0F]);
                output.push_back(hex[byte & 0x0F]);
            }

            return output;
        }

        static std::string BytesToHexUpper(const BYTE* bytes, DWORD length) {
            std::ostringstream out;
            out << std::uppercase << std::hex << std::setfill('0');
            for (DWORD i = 0; i < length; ++i) {
                out << std::setw(2) << static_cast<int>(bytes[i]);
            }
            return out.str();
        }

        static std::string Sha256Hex(const std::string& data) {
            BCRYPT_ALG_HANDLE algHandle = nullptr;
            BCRYPT_HASH_HANDLE hashHandle = nullptr;
            DWORD objectLength = 0;
            DWORD resultLength = 0;
            DWORD hashLength = 0;

            if (BCryptOpenAlgorithmProvider(&algHandle, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
                throw std::runtime_error("Failed to open SHA-256 provider");
            }

            if (BCryptGetProperty(algHandle, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &resultLength, 0) != 0 ||
                BCryptGetProperty(algHandle, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLength), sizeof(hashLength), &resultLength, 0) != 0) {
                BCryptCloseAlgorithmProvider(algHandle, 0);
                throw std::runtime_error("Failed to query SHA-256 properties");
            }

            std::vector<BYTE> hashObject(objectLength);
            std::vector<BYTE> hashBytes(hashLength);

            if (BCryptCreateHash(algHandle, &hashHandle, hashObject.data(), objectLength, nullptr, 0, 0) != 0 ||
                BCryptHashData(hashHandle, reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())), static_cast<ULONG>(data.size()), 0) != 0 ||
                BCryptFinishHash(hashHandle, hashBytes.data(), hashLength, 0) != 0) {
                if (hashHandle) {
                    BCryptDestroyHash(hashHandle);
                }
                BCryptCloseAlgorithmProvider(algHandle, 0);
                throw std::runtime_error("Failed to hash data");
            }

            BCryptDestroyHash(hashHandle);
            BCryptCloseAlgorithmProvider(algHandle, 0);
            return BytesToHexUpper(hashBytes.data(), hashLength);
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

        static std::vector<BYTE> Base64ToBytes(std::string value) {
            std::replace(value.begin(), value.end(), '-', '+');
            std::replace(value.begin(), value.end(), '_', '/');
            while (value.length() % 4 != 0) {
                value.push_back('=');
            }

            DWORD needed = 0;
            if (!CryptStringToBinaryA(value.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &needed, nullptr, nullptr)) {
                return {};
            }

            std::vector<BYTE> output(needed);
            if (!CryptStringToBinaryA(value.c_str(), 0, CRYPT_STRING_BASE64, output.data(), &needed, nullptr, nullptr)) {
                return {};
            }

            output.resize(needed);
            return output;
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

        RequestContext CreateRequest(const std::string& endpoint, const std::map<std::string, std::string>& fields) const {
            RequestContext ctx;
            ctx.Endpoint = endpoint;
            ctx.Nonce = GenerateRandomHex();
            ctx.Timestamp = std::to_string(CurrentUnixTimeSeconds());

            auto payload = fields;
            payload.emplace("clientNonce", ctx.Nonce);
            payload.emplace("clientTimestamp", ctx.Timestamp);

            ctx.JsonBody = BuildRequestJson(payload);
            return ctx;
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
            result.RequestNonce = ExtractJsonString(jsonStr, "requestNonce");
            result.ServerTimestamp = ExtractJsonString(jsonStr, "serverTimestamp");
            result.Signature = ExtractJsonString(jsonStr, "signature");
            result.Variables = ParseStringMap(ExtractRawJsonObject(jsonStr, "variables"));
            return result;
        }

        std::string BuildSignaturePayload(const RequestContext& request, const ApiResponse& response) const {
            std::ostringstream variableStream;
            for (const auto& [key, value] : response.Variables) {
                variableStream << key << "=" << value << "\n";
            }

            std::ostringstream payload;
            payload << "endpoint=" << Sha256Hex(request.Endpoint) << "\n";
            payload << "requestNonce=" << Sha256Hex(request.Nonce) << "\n";
            payload << "serverTimestamp=" << Sha256Hex(response.ServerTimestamp) << "\n";
            payload << "success=" << (response.Success ? "1" : "0") << "\n";
            payload << "message=" << Sha256Hex(response.Message) << "\n";
            payload << "username=" << Sha256Hex(response.Username) << "\n";
            payload << "subscription=" << Sha256Hex(response.Subscription) << "\n";
            payload << "expiry=" << Sha256Hex(response.Expiry) << "\n";
            payload << "serverVersion=" << Sha256Hex(response.ServerVersion) << "\n";
            payload << "value=" << Sha256Hex(response.Value) << "\n";
            payload << "variables=" << Sha256Hex(variableStream.str()) << "\n";
            return payload.str();
        }

        bool VerifyResponseSignature(const RequestContext& request, const ApiResponse& response) const {
            if (!EnforceStrictSecurity) {
                return true;
            }

            if (ResponseSigningPublicKeyPem.empty()) {
                return false;
            }

            if (response.RequestNonce.empty() || response.ServerTimestamp.empty() || response.Signature.empty()) {
                return false;
            }

            if (response.RequestNonce != request.Nonce) {
                return false;
            }

            long long now = CurrentUnixTimeSeconds();
            long long serverTime = 0;
            try {
                serverTime = std::stoll(response.ServerTimestamp);
            }
            catch (...) {
                return false;
            }

            if (std::llabs(now - serverTime) > AllowedClockSkewSeconds) {
                return false;
            }

            std::vector<BYTE> signature = Base64ToBytes(response.Signature);
            if (signature.empty()) {
                return false;
            }

            std::string pem = ResponseSigningPublicKeyPem;
            const std::string header = "-----BEGIN PUBLIC KEY-----";
            const std::string footer = "-----END PUBLIC KEY-----";

            std::size_t headerPos = pem.find(header);
            std::size_t footerPos = pem.find(footer);
            if (headerPos != std::string::npos && footerPos != std::string::npos) {
                pem = pem.substr(headerPos + header.length(), footerPos - (headerPos + header.length()));
            }

            pem.erase(std::remove_if(pem.begin(), pem.end(), [](unsigned char c) {
                return std::isspace(c) != 0;
                }), pem.end());

            std::vector<BYTE> publicKeyDer = Base64ToBytes(pem);
            if (publicKeyDer.empty()) {
                return false;
            }

            CERT_PUBLIC_KEY_INFO* publicKeyInfo = nullptr;
            DWORD publicKeyInfoSize = 0;
            if (!CryptDecodeObjectEx(
                X509_ASN_ENCODING,
                X509_PUBLIC_KEY_INFO,
                publicKeyDer.data(),
                static_cast<DWORD>(publicKeyDer.size()),
                CRYPT_DECODE_ALLOC_FLAG,
                nullptr,
                &publicKeyInfo,
                &publicKeyInfoSize)) {
                return false;
            }

            BCRYPT_KEY_HANDLE keyHandle = nullptr;
            bool verified = false;

            if (CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, publicKeyInfo, 0, nullptr, &keyHandle)) {
                BCRYPT_PKCS1_PADDING_INFO paddingInfo{ BCRYPT_SHA256_ALGORITHM };
                std::string payload = BuildSignaturePayload(request, response);
                std::string digestHex = Sha256Hex(payload);

                std::vector<BYTE> digest;
                digest.reserve(digestHex.length() / 2);
                for (std::size_t i = 0; i + 1 < digestHex.length(); i += 2) {
                    unsigned int byteValue = 0;
                    std::stringstream stream;
                    stream << std::hex << digestHex.substr(i, 2);
                    stream >> byteValue;
                    digest.push_back(static_cast<BYTE>(byteValue));
                }

                verified = BCryptVerifySignature(
                    keyHandle,
                    &paddingInfo,
                    digest.data(),
                    static_cast<ULONG>(digest.size()),
                    signature.data(),
                    static_cast<ULONG>(signature.size()),
                    BCRYPT_PAD_PKCS1) == 0;
            }

            if (keyHandle) {
                BCryptDestroyKey(keyHandle);
            }

            if (publicKeyInfo) {
                LocalFree(publicKeyInfo);
            }

            return verified;
        }

        std::string HttpRequest(const RequestContext& request) {
            HINTERNET hInternet = InternetOpenA("TXA", INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0);
            if (!hInternet) {
                return "";
            }

            DWORD timeoutMs = 15000;
            InternetSetOptionA(hInternet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeoutMs, sizeof(timeoutMs));
            InternetSetOptionA(hInternet, INTERNET_OPTION_SEND_TIMEOUT, &timeoutMs, sizeof(timeoutMs));
            InternetSetOptionA(hInternet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeoutMs, sizeof(timeoutMs));

            HINTERNET hConnect = InternetConnectA(
                hInternet,
                ApiHost.c_str(),
                INTERNET_DEFAULT_HTTPS_PORT,
                nullptr,
                nullptr,
                INTERNET_SERVICE_HTTP,
                0,
                0);

            if (!hConnect) {
                InternetCloseHandle(hInternet);
                return "";
            }

            std::string path = "/" + request.Endpoint;
            HINTERNET hRequest = HttpOpenRequestA(
                hConnect,
                "POST",
                path.c_str(),
                nullptr,
                nullptr,
                nullptr,
                INTERNET_FLAG_SECURE |
                INTERNET_FLAG_RELOAD |
                INTERNET_FLAG_NO_CACHE_WRITE |
                INTERNET_FLAG_NO_AUTO_REDIRECT |
                INTERNET_FLAG_NO_COOKIES,
                0);

            if (!hRequest) {
                InternetCloseHandle(hConnect);
                InternetCloseHandle(hInternet);
                return "";
            }

            std::string headers =
                "Content-Type: application/json\r\n"
                "Accept: application/json\r\n"
                "X-TXA-Nonce: " + request.Nonce + "\r\n"
                "X-TXA-Timestamp: " + request.Timestamp + "\r\n";

            BOOL sent = HttpSendRequestA(
                hRequest,
                headers.c_str(),
                static_cast<DWORD>(headers.length()),
                reinterpret_cast<LPVOID>(const_cast<char*>(request.JsonBody.data())),
                static_cast<DWORD>(request.JsonBody.length()));

            std::string response;
            if (sent) {
                char buffer[4096];
                DWORD bytesRead = 0;
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

        ApiResponse PerformSecureRequest(const RequestContext& request) {
            std::string rawResponse = HttpRequest(request);
            if (rawResponse.empty()) {
                throw std::runtime_error(TamperDetectedMessage());
            }

            ApiResponse response = ParseResponse(rawResponse);
            if (!VerifyResponseSignature(request, response)) {
                throw std::runtime_error(TamperDetectedMessage());
            }

            return response;
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
            RequestContext request = CreateRequest("isapplicationpaused", {
                {"secret", Secret},
                {"appName", AppName}
                });

            ApiResponse result = PerformSecureRequest(request);
            return result.Success && result.Message == "APPLICATION_PAUSED";
        }

        std::pair<bool, std::string> CheckVersion() {
            RequestContext request = CreateRequest("versioncheck", {
                {"secret", Secret},
                {"appName", AppName},
                {"appVersion", Version}
                });

            ApiResponse result = PerformSecureRequest(request);
            if (result.Success && result.Message == "VERSION_OK") {
                return { true, Version };
            }

            if (result.Message == "VERSION_MISMATCH" && !result.ServerVersion.empty()) {
                return { false, result.ServerVersion };
            }

            return { false, "Unknown" };
        }

        bool LoadAppVariables() {
            RequestContext request = CreateRequest("getvariables", {
                {"secret", Secret},
                {"appName", AppName}
                });

            ApiResponse result = PerformSecureRequest(request);
            if (!result.Success || result.Message == "NO_VARIABLES") {
                return false;
            }

            std::lock_guard<std::mutex> lock(varMutex);
            Variables = result.Variables;
            return true;
        }

        void EnsureSecurityConfiguration() {
            if (!EnforceStrictSecurity) {
                return;
            }

            if (ResponseSigningPublicKeyPem.empty()) {
                ShowError(_xor_("Security Alert").str(), TamperDetectedMessage());
                ExitProcess(0);
            }
        }

    public:
        Auth(const std::string& name, const std::string& secret, const std::string& version)
            : AppName(name), Secret(secret), Version(version) {
        }

        void SetResponseSigningPublicKeyPem(const std::string& pem) {
            ResponseSigningPublicKeyPem = TrimCopy(pem);
        }

        bool SetResponseSigningPublicKeyFromFile(const std::string& path) {
            std::ifstream file(path, std::ios::in | std::ios::binary);
            if (!file.is_open()) {
                return false;
            }

            std::ostringstream buffer;
            buffer << file.rdbuf();
            ResponseSigningPublicKeyPem = TrimCopy(buffer.str());
            return !ResponseSigningPublicKeyPem.empty();
        }

        bool LoadResponseSigningPublicKeyFromEnvironment(const std::string& envVar = "TXA_RESPONSE_SIGNING_PUBLIC_KEY_PEM") {
            char* value = nullptr;
            std::size_t size = 0;
            if (_dupenv_s(&value, &size, envVar.c_str()) != 0 || !value || size == 0) {
                if (value) {
                    free(value);
                }
                return false;
            }

            ResponseSigningPublicKeyPem = TrimCopy(std::string(value));
            free(value);
            return !ResponseSigningPublicKeyPem.empty();
        }

        bool HasResponseSigningPublicKey() const {
            return !ResponseSigningPublicKeyPem.empty();
        }

        void SetStrictSecurity(bool enabled) {
            EnforceStrictSecurity = enabled;
        }

        void SetAllowedClockSkewSeconds(long long seconds) {
            AllowedClockSkewSeconds = seconds > 0 ? seconds : 120;
        }

        void Init() {
            if (AppName.empty() || Secret.empty() || Version.empty()) {
                ShowError("TXA Auth Error", "AppName/Secret/Version missing");
                ExitProcess(0);
            }

            EnsureSecurityConfiguration();

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
                    SetResponseMessage("TXA SDK initialized with signed-response verification.");
                }
                catch (const std::exception& ex) {
                    ShowError(_xor_("Security Alert").str(), TamperDetectedMessage());
                    ExitProcess(0);
                }
                catch (...) {
                    ShowError(_xor_("Security Alert").str(), TamperDetectedMessage());
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
                RequestContext request = CreateRequest("login", {
                    {"username", username},
                    {"password", password},
                    {"secret", Secret},
                    {"appName", AppName},
                    {"appVersion", Version},
                    {"hwid", GetHWID()}
                    });

                ApiResponse apiResp = PerformSecureRequest(request);
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
                SetResponseMessage(TamperDetectedMessage());
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
                RequestContext request = CreateRequest("register", {
                    {"username", username},
                    {"password", password},
                    {"licenseKey", license},
                    {"secret", Secret},
                    {"appName", AppName},
                    {"appVersion", Version},
                    {"hwid", GetHWID()}
                    });

                ApiResponse apiResp = PerformSecureRequest(request);
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
                SetResponseMessage(TamperDetectedMessage());
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
                RequestContext request = CreateRequest("getvariable", {
                    {"secret", Secret},
                    {"appName", AppName},
                    {"appVersion", Version},
                    {"varName", name}
                    });

                ApiResponse apiResp = PerformSecureRequest(request);
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
                SetResponseMessage(TamperDetectedMessage());
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
                SetResponseMessage(TamperDetectedMessage());
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
