#ifndef NETWORK_PROTOCOL_H
#define NETWORK_PROTOCOL_H

#include "vector.h"
#include "HashMap.h"
#include <string>

using namespace std;

string escapeJsonString(const string& str);

struct Request {
    string database;
    string operation;
    string collection;
    Vector<string> data;
    string query;
    
    string toJson() const;
    static Request fromJson(const string& json);
};

struct Response {
    string status;
    string message;
    Vector<string> data;
    int count;
    
    string toJson() const;
    static Response fromJson(const string& json);
};

#endif