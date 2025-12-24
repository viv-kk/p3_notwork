#include "network_protocol.h"
#include "JsonParser.h"
#include <sstream>
#include <iostream>
#include <algorithm> 
using namespace std;

// Вспомогательная функция для экранирования строк JSON
string escapeJsonString(const string& str) {
    ostringstream escaped;
    for (char c : str) {
        switch (c) {
            case '"':  escaped << "\\\""; break;
            case '\\': escaped << "\\\\"; break;
            case '\b': escaped << "\\b"; break;
            case '\f': escaped << "\\f"; break;
            case '\n': escaped << "\\n"; break;
            case '\r': escaped << "\\r"; break;
            case '\t': escaped << "\\t"; break;
            default:   escaped << c; break;
        }
    }
    return escaped.str();
}

string Request::toJson() const {
    ostringstream json;
    json << "{";
    json << "\"database\":\"" << database << "\",";
    json << "\"operation\":\"" << operation << "\",";
    json << "\"collection\":\"" << collection << "\",";
    
    // query должен быть строкой или JSON объектом
    if (!query.empty()) {
        json << "\"query\":";
        // Если query начинается с {, это JSON объект
        if (query[0] == '{' || query[0] == '[') {
            json << query;
        } else {
            json << "\"" << escapeJsonString(query) << "\"";
        }
        json << ",";
    }
    
    json << "\"data\":[";
    for (size_t i = 0; i < data.size(); ++i) {
        if (i > 0) json << ",";
        
        // Проверяем, является ли data[i] JSON объектом/массивом
        if (!data[i].empty() && 
            ((data[i][0] == '{' && data[i][data[i].size()-1] == '}') ||
             (data[i][0] == '[' && data[i][data[i].size()-1] == ']'))) {
            
            // Проверяем валидность JSON
            JsonParser parser;
            try {
                if (data[i][0] == '{') {
                    HashMap<string, string> parsed = parser.parse(data[i]);
                    json << data[i];  // Это валидный JSON объект
                } else if (data[i][0] == '[') {
                    Vector<HashMap<string, string>> parsed = parser.parseArray(data[i]);
                    json << data[i];  // Это валидный JSON массив
                }
            } catch (...) {
                // Если не парсится как JSON, обрабатываем как строку
                json << "\"" << escapeJsonString(data[i]) << "\"";
            }
        } else {
            // Это обычная строка, экранируем
            json << "\"" << escapeJsonString(data[i]) << "\"";
        }
    }
    json << "]}";
    return json.str();
}

Request Request::fromJson(const string& jsonStr) {    
    Request req;
    JsonParser parser;
    try {
        HashMap<string, string> parsed = parser.parse(jsonStr);
        string value;
        
        if (parsed.contains("database")) {
            if (parsed.get("database", value)) {
                req.database = value;
            }
        }
        
        if (parsed.contains("operation")) {
            if (parsed.get("operation", value)) {
                req.operation = value;
            }
        }
        
        if (parsed.contains("collection")) {
            if (parsed.get("collection", value)) {
                req.collection = value;
            }
        }
        
        if (parsed.contains("query")) {
            if (parsed.get("query", value)) {
                req.query = value;
            }
        }
        
        if (parsed.contains("data")) {
            string dataStr;
            if (parsed.get("data", dataStr)) {
                if (dataStr.size() >= 2 && dataStr[0] == '[' && dataStr[dataStr.size()-1] == ']') {
                    Vector<HashMap<string, string>> dataArray = parser.parseArray(dataStr);
                    for (size_t i = 0; i < dataArray.size(); i++) {
                        HashMap<string, string> item = dataArray[i];
                        ostringstream itemJson;
                        itemJson << "{";
                        auto items = item.items();
                        for (size_t j = 0; j < items.size(); j++) {
                            if (j > 0) itemJson << ",";
                            itemJson << "\"" << items[j].first << "\":";
                            
                            string val = items[j].second;
                            if (val.empty() || 
                                (val[0] != '{' && val[0] != '[' && 
                                 val != "true" && val != "false" && val != "null" &&
                                 !isdigit(val[0]) && val[0] != '-')) {
                                itemJson << "\"" << val << "\"";
                            } else {
                                itemJson << val;
                            }
                        }
                        itemJson << "}";
                        req.data.push_back(itemJson.str());
                    }
                }
            }
        }
    } catch (const exception& e) {
        cerr << "[REQUEST][ERROR] Failed to parse JSON: " << e.what() << endl;
    }
    
    return req;
}

string Response::toJson() const {
    ostringstream json;
    json << "{";
    json << "\"status\":\"" << status << "\",";
    json << "\"message\":\"" << escapeJsonString(message) << "\",";
    json << "\"count\":" << count << ",";
    json << "\"data\":[";
    for (size_t i = 0; i < data.size(); ++i) {
        if (i > 0) json << ",";
        
        // Проверяем, является ли data[i] JSON объектом/массивом
        if (!data[i].empty() && 
            ((data[i][0] == '{' && data[i][data[i].size()-1] == '}') ||
             (data[i][0] == '[' && data[i][data[i].size()-1] == ']'))) {
            
            // Проверяем валидность JSON
            JsonParser parser;
            try {
                if (data[i][0] == '{') {
                    HashMap<string, string> parsed = parser.parse(data[i]);
                    json << data[i];  // Это валидный JSON объект
                } else if (data[i][0] == '[') {
                    Vector<HashMap<string, string>> parsed = parser.parseArray(data[i]);
                    json << data[i];  // Это валидный JSON массив
                }
            } catch (...) {
                // Если не парсится как JSON, обрабатываем как строку
                json << "\"" << escapeJsonString(data[i]) << "\"";
            }
        } else {
            // Это обычная строка, экранируем
            json << "\"" << escapeJsonString(data[i]) << "\"";
        }
    }
    json << "]}";
    return json.str();
}

Response Response::fromJson(const string& json) {
    Response resp;
    JsonParser parser;
    try {
        HashMap<string, string> parsed = parser.parse(json);
        
        string value;
        
        if (parsed.contains("status")) {
            if (parsed.get("status", value)) {
                resp.status = value;
            }
        }
        
        if (parsed.contains("message")) {
            if (parsed.get("message", value)) {
                resp.message = value;
            }
        }
        
        if (parsed.contains("count")) {
            string countStr;
            if (parsed.get("count", countStr)) {
                try {
                    resp.count = stoi(countStr);
                } catch (const exception& e) {
                    cerr << "[RESPONSE][ERROR] Invalid count value: " << countStr << endl;
                    resp.count = 0;
                }
            }
        }
        
        if (parsed.contains("data")) {
            string dataStr;
            if (parsed.get("data", dataStr)) {
                if (dataStr.size() >= 2 && dataStr[0] == '[' && dataStr[dataStr.size()-1] == ']') {
                    string extracted = parser.extractJsonValue(dataStr);
                    if (!extracted.empty() && extracted[0] == '[') {
                        size_t pos = 1;
                        while (pos < extracted.length()) {
                            while (pos < extracted.length() && isspace(extracted[pos])) pos++;
                            
                            if (extracted[pos] == ']') break;
                            
                            if (extracted[pos] == '"') {
                                pos++;
                                size_t start = pos;
                                while (pos < extracted.length() && extracted[pos] != '"') {
                                    if (extracted[pos] == '\\') pos++;
                                    pos++;
                                }
                                if (pos < extracted.length()) {
                                    string item = extracted.substr(start, pos - start);
                                    resp.data.push_back(item);
                                    pos++;
                                }
                            } else if (extracted[pos] == '{') {
                                size_t start = pos;
                                int braceCount = 0;
                                do {
                                    if (extracted[pos] == '{') braceCount++;
                                    else if (extracted[pos] == '}') braceCount--;
                                    pos++;
                                } while (pos < extracted.length() && braceCount > 0);
                                
                                if (braceCount == 0) {
                                    string item = extracted.substr(start, pos - start);
                                    resp.data.push_back(item);
                                }
                            } else {
                                pos++;
                            }
                            
                            while (pos < extracted.length() && isspace(extracted[pos])) pos++;
                            if (pos < extracted.length() && extracted[pos] == ',') pos++;
                        }
                    }
                }
            }
        }
    } catch (const exception& e) {
        cerr << "[RESPONSE][ERROR] Failed to parse JSON response: " << e.what() << endl;
        resp.status = "error";
        resp.message = "Failed to parse response: " + string(e.what());
    }
    
    return resp;
}

bool isValidJsonString(const string& str) {
    if (str.empty()) return false;
    
    JsonParser parser;
    try {
        if (str[0] == '{') {
            HashMap<string, string> parsed = parser.parse(str);
            return true;
        } else if (str[0] == '[') {
            Vector<HashMap<string, string>> parsed = parser.parseArray(str);
            return true;
        }
    } catch (...) {
        return false;
    }
    return false;
}