#include "collection.h"
#include "JsonParser.h"
#include <fstream>
#include <cstdio>
#include <string>

Collection::Collection(const string& collectionName) : name(collectionName) {
    loadFromDisk();
}

bool Collection::loadFromDisk() {
    string filename = getFilename();
    std::ifstream file(filename.c_str());
    if (!file.is_open()) {
        return true;
    }
    
    string jsonContent;
    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        jsonContent += string(buffer, file.gcount());
    }
    if (file.gcount() > 0) {
        jsonContent += string(buffer, file.gcount());
    }
    file.close();
    
    if (jsonContent.empty()) {
        return true;
    }
    
    //парсинг массива доков
    JsonParser parser;
    Vector<HashMap<string, string>> documentsArray = parser.parseArray(jsonContent);

    documents.clear();
    
    for (size_t i = 0; i < documentsArray.size(); i++) {//загрузка доков из массива
        HashMap<string, string> docData = documentsArray[i];
        string docId;
        
        if (!docData.get("_id", docId)) {
            static int counter = 0;
            docId = "doc_" + to_string(counter++);
        }
        
        Document doc(docData, docId);//создаем документ объекты в хэш мап
        documents.put(docId, doc);
    }
    
    return true;
}

bool Collection::saveToDisk() {
    string filename = getFilename();
    std::ofstream file(filename.c_str());
    if (!file.is_open()) {
        return false;
    }
    
    file << "[" << std::endl;
    auto items = documents.items();
    bool first = true;
    
    for (size_t i = 0; i < items.size(); i++) {
        if (!first) {
            file << "," << std::endl;
        }
        string jsonStr = items[i].second.to_json();
        file << " " << jsonStr.c_str();
        first = false;
    }
    file << "]" << std::endl;
    file.close();
    return true;
}

string Collection::getFilename() const {
    return name + ".json";
}

string Collection::insert(const string& jsonData) {
    JsonParser parser;
    HashMap<string, string> newDocData = parser.parse(jsonData);

    static int counter = 0;
    string docId = "doc_" + to_string(static_cast<int>(std::time(nullptr))) + 
                   "_" + to_string(std::rand() % 10000) + "_" + to_string(counter++);

    newDocData.put("_id", docId);
    
    Document newDoc(newDocData, docId);
    documents.put(docId, newDoc);
    
    if (saveToDisk()) {
        return string("Document inserted successfully.");
    } else {
        return string("Error: Failed to save document to disk.");
    }
}

Vector<Document> Collection::find(const QueryCondition& condition) {
    Vector<Document> results;
    auto items = documents.items();//все доки коллекции
    
    for (size_t i = 0; i < items.size(); i++) {
        if (items[i].second.matchesCondition(condition)) {
            results.push_back(items[i].second);//добавляем подходящие доки
        }
    }
    return results;
}

string Collection::remove(const QueryCondition& condition) {
    Vector<Document> toRemove = find(condition);// находим что удалить
    size_t count = toRemove.size();
    
    for (size_t i = 0; i < toRemove.size(); i++) {
        documents.remove(toRemove[i].getId());//удаляем из памяти
    }
    
    if (count > 0) {
        if (saveToDisk()) {
            return to_string(count) + string(" document(s) deleted successfully.");
        } else {
            return string("Error: Failed to save changes to disk.");
        }
    } else {
        return "No documents found matching the condition.";
    }
}

size_t Collection::size() const {
    return documents.size();
}
