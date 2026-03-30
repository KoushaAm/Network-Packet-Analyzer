#include "logger.hpp"
#include <fstream>
#include <iostream>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <fcntl.h>
#include <unistd.h>

using namespace std; 

static string currentTime() {
    auto now = std::time(nullptr);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

Logger::~Logger() {
    // Destructor
    this->filename = "";
}

Logger::Logger(const std::string & filename, bool rewriteCSV) {
    // open csv log file 
    if (rewriteCSV) {
        std::ofstream csv(filename);
        if (csv.is_open()) {
            csv << "Timestamp,Protocol,SrcIP,SrcPort,DstIP,DstPort,Length\n";
            csv.close();
        } else {
            std::ofstream csv(filename, std::ios::app);
            if (!csv.is_open()) {
                std::cerr << "Failed to open log file: " << filename << std::endl;
            } else {
                // if file is new
                if (csv.tellp() == 0) {
                    csv << "timestamp,protocol,src_ip,src_port,dst_ip,dst_port,length\n";
                }
                csv.close();
            }
        }
    }
}

void Logger::logPacket(const Packet & pkt) {
    std::ofstream csv("packets.csv", std::ios::app);
    if (!csv.is_open()) return;

    csv << pkt.timestamp << ","
        << pkt.protocol << ","
        << pkt.srcIP << ","
        << pkt.srcPort << ","
        << pkt.dstIP << ","
        << pkt.dstPort << ","
        << pkt.length
        << "\n";

    csv.close();

    // stream to dashboard via named pipe (non-blocking — silently skipped if dashboard isn't running)
    std::ostringstream line;
    line << pkt.timestamp << ","
         << pkt.protocol << ","
         << pkt.srcIP << ","
         << pkt.srcPort << ","
         << pkt.dstIP << ","
         << pkt.dstPort << ","
         << pkt.length << "\n";

    int fd = open("/tmp/packet_stream", O_WRONLY | O_NONBLOCK);
    if (fd != -1) {
        std::string s = line.str();
        write(fd, s.c_str(), s.size());
        close(fd);
    }
}

void Logger::logStats(int tcp, int udp, int icmp, int other, long totalBytes) {
    std::ofstream out("stats.log", std::ios::app);
    if (!out.is_open()) return;

    out << "[" << currentTime() << "] "
    << "Stats: TCP=" << tcp
    << " UDP=" << udp
    << " ICMP=" << icmp
    << " Other=" << other
    << " TotalBytes=" << totalBytes
    << std::endl;

    out.close();
}

void Logger::log(LogLevel level, const std::string & message) {
    std::ofstream out("app.log", std::ios::app);
    if (!out.is_open()) return;

    std::string levelStr;
    switch (level) {
        case LogLevel::INFO: levelStr = "INFO"; break;
        case LogLevel::WARNING: levelStr = "WARNING"; break;
        case LogLevel::ERROR: levelStr = "ERROR"; break;
    }

    out << "[" << currentTime() << "] "
        << "[" << levelStr << "] "
        << message << std::endl;

    out.close();
}
