#ifndef COLLECTION_H
#define COLLECTION_H

#include "document.h"
#include "HashMap.h"
#include "QueryCondition.h"
#include <fstream>
#include <string>
using namespace std;

class Collection {
private:
    string name;
    HashMap<string, Document> documents;
    
    string getFilename() const;

public:
    Collection(const string& collectionName);
    Collection(const Collection& other) = default; 
    Collection& operator=(const Collection& other) = default; 
    Collection(Collection&& other) noexcept = default; 
    Collection& operator=(Collection&& other) noexcept = default;
    bool loadFromDisk();
    bool saveToDisk();
    string insert(const string& jsonData);
    Vector<Document> find(const QueryCondition& condition);
    string remove(const QueryCondition& condition);
    size_t size() const;
};

#endif
