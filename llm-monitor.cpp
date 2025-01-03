#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include "LlamaLocal.h" // Ensure this include reflects the actual Llama Local library

// Script that uses LlamaLocal LLM to monitor FreePBX / Asterisk for Cyber Security Threats and provide report

struct LogEntry {
    std::string threatType;
    std::string details;
    std::string timestamp;
};

// Function to read Asterisk logs
std::vector<std::string> readLogs(const std::string& logDirectory) {
    std::vector<std::string> logs;
    std::string line;
    // Typical Asterisk log files, adjust as necessary
    std::string filenames[] = {"messages", "error", "full"};

    for (const auto& filename : filenames) {
        std::ifstream file(logDirectory + filename);
        while (getline(file, line)) {
            logs.push_back(line);
        }
    }
    return logs;
}

// Analyze logs using Llama Local
std::vector<LogEntry> analyzeLogs(const std::vector<std::string>& logs) {
    LlamaLocal analyzer;
    std::vector<LogEntry> results;

    for (const auto& log : logs) {
        LogEntry entry = analyzer.analyze(log); // Assuming 'analyze' returns a LogEntry
        results.push_back(entry);
    }
    
    return results;
}

// Save results to CSV
void saveToCSV(const std::vector<LogEntry>& entries, const std::string& outfile) {
    std::ofstream file(outfile);
    file << "Threat Type,Details,Timestamp\n";
    
    for (const auto& entry : entries) {
        file << entry.threatType << "," << entry.details << "," << entry.timestamp << "\n";
    }
}

int main() {
    std::string logDirectory = "/var/log/asterisk/";
    std::string csvFilename = "analysis_results.csv";
    
    auto logs = readLogs(logDirectory);
    auto analyzedResults = analyzeLogs(logs);
    saveToCSV(analyzedResults, csvFilename);

    return 0;
}
