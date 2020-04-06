#include "linux_parser.h"

#include <dirent.h>
#include <unistd.h>

#include <numeric>
#include <string>
#include <vector>

using std::stof;
using std::string;
using std::to_string;
using std::vector;

// DONE: An example of how to read data from the filesystem
string LinuxParser::OperatingSystem() {
  string line;
  string key;
  string value;
  std::ifstream filestream(kOSPath);
  if (filestream.is_open()) {
    while (std::getline(filestream, line)) {
      std::replace(line.begin(), line.end(), ' ', '_');
      std::replace(line.begin(), line.end(), '=', ' ');
      std::replace(line.begin(), line.end(), '"', ' ');
      std::istringstream linestream(line);
      while (linestream >> key >> value) {
        if (key == "PRETTY_NAME") {
          std::replace(value.begin(), value.end(), '_', ' ');
          return value;
        }
      }
    }
  }
  return value;
}

// DONE: An example of how to read data from the filesystem
string LinuxParser::Kernel() {
  string os, version, kernel;
  string line;
  std::ifstream stream(kProcDirectory + kVersionFilename);
  if (stream.is_open()) {
    std::getline(stream, line);
    std::istringstream linestream(line);
    linestream >> os >> version >> kernel;
  }
  return kernel;
}

// BONUS: Update this to use std::filesystem
vector<int> LinuxParser::Pids() {
  vector<int> pids;
  DIR* directory = opendir(kProcDirectory.c_str());
  struct dirent* file;
  while ((file = readdir(directory)) != nullptr) {
    // Is this a directory?
    if (file->d_type == DT_DIR) {
      // Is every character of the name a digit?
      string filename(file->d_name);
      if (std::all_of(filename.begin(), filename.end(), isdigit)) {
        int pid = stoi(filename);
        pids.push_back(pid);
      }
    }
  }
  closedir(directory);
  return pids;
}

// TODO: Read and return the system memory utilization
float LinuxParser::MemoryUtilization() {
  float MemTotal, MemFree, value;
  string key, kb;
  string line;
  std::ifstream filestream(kProcDirectory + kMeminfoFilename);
  if (filestream.is_open()) {
    while (std::getline(filestream, line)) {
      std::replace(line.begin(), line.end(), ':', ' ');
      std::istringstream linestream(line);
      while (linestream >> key >> value >> kb) {
        if (key == "MemTotal") {
          MemTotal = value;
        }
        if (key == "MemFree") {
          MemFree = value;
          return (MemTotal - MemFree) / MemTotal;
        }
      }
    }
  }
  return 0;
}

// TODO: Read and return the system uptime
long LinuxParser::UpTime() {
  long uptimeSystem;  //, uptimeIdle;
  string line;
  std::ifstream filestream(kProcDirectory + kUptimeFilename);
  if (filestream.is_open()) {
    getline(filestream, line);
    std::istringstream linestream(line);
    linestream >> uptimeSystem;  // >> uptimeIdle;
  }

  return uptimeSystem;
}

// TODO: Read and return the number of jiffies for the system
long LinuxParser::Jiffies() {
  return LinuxParser::ActiveJiffies() + LinuxParser::IdleJiffies();
}

// TODO: Read and return the number of active jiffies for a PID
// REMOVE: [[maybe_unused]] once you define the function
long LinuxParser::ActiveJiffies(int pid) {
  std::ifstream filestream(LinuxParser::kProcDirectory + to_string(pid) +
                           LinuxParser::kStatFilename);  // /proc/[PID]/stat
  string value;
  long utime, stime, cutime, cstime;

  if (filestream.is_open()) {
    for (int i = 1; i < 23; i++) {
      std::getline(filestream, value, ' ');
      switch (i) {
        case 14:
          utime = stol(value);
          break;
        case 15:
          stime = stol(value);
          break;
        case 16:
          cutime = stol(value);
          break;
        case 17:
          cstime = stol(value);
          break;
        default:
          break;
      }
    }
  }

  return utime + stime + cutime + cstime;
}

// TODO: Read and return the number of active jiffies for the system
long LinuxParser::ActiveJiffies() {
  std::vector<long> times = LinuxParser::CpuTimes();
  return std::accumulate(times.begin(), times.end(), 0);
}

// TODO: Read and return the number of idle jiffies for the system
long LinuxParser::IdleJiffies() {
  long Idle, Iowait;
  std::string line;
  std::string DeleteMe;
  std::ifstream filestream(LinuxParser::kProcDirectory +
                           LinuxParser::kStatFilename);
  if (filestream.is_open()) {
    std::getline(filestream, line);
    std::istringstream linestream(line);
    linestream >> DeleteMe >> DeleteMe >> DeleteMe >> DeleteMe >> Idle >>
        Iowait;
  }
  return (Idle + Iowait);
}

// TODO: Read and return CPU utilization
vector<string> LinuxParser::CpuUtilization() {
  std::vector<string> times;
  std::ifstream filestream(kProcDirectory + kStatFilename);
  if (filestream.is_open()) {
    filestream.ignore(5, ' ');  // Skip the 'cpu' prefix.
    for (string time; filestream >> time; times.push_back(time))
      ;
  }
  return times;
}

// TODO: Read and return the total number of processes
int LinuxParser::TotalProcesses() {
  int value, processes;
  string key, line;

  std::ifstream filestream(kProcDirectory + kStatFilename);
  if (filestream.is_open()) {
    filestream.seekg(20);
    while (std::getline(filestream, line)) {
      std::istringstream linestream(line);
      linestream >> key >> value;

      if (key == "processes") {
        processes = value;
        return processes;
      }
    }
  }
  return 0;
}

// TODO: Read and return the number of running processes
int LinuxParser::RunningProcesses() {
  int value, procs_running;
  string key, line;

  std::ifstream filestream(kProcDirectory + kStatFilename);
  if (filestream.is_open()) {
    filestream.seekg(20);
    while (std::getline(filestream, line)) {
      std::istringstream linestream(line);
      linestream >> key >> value;

      if (key == "procs_running") {
        procs_running = value;
        return procs_running;
      }
    }
  }
  return 0;
}

// CPU Utilization for a specific process
float LinuxParser::CpuUtilization(int pid) {
  long upTime = LinuxParser::UpTime();               // System Uptime
  long totalTime = LinuxParser::ActiveJiffies(pid);  // Process total time
  long startTime = LinuxParser::UpTime(pid);         // Process Uptime
  long seconds = upTime - (startTime / sysconf(_SC_CLK_TCK));

  return ((float)(totalTime / sysconf(_SC_CLK_TCK))) / (float)seconds;
}

// TODO: Read and return the command associated with a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::Command(int pid) {
  string command;

  std::ifstream filestream(kProcDirectory + std::to_string(pid) +
                           kCmdlineFilename);
  if (filestream.is_open()) {
    std::getline(filestream, command);
  }

  return command;
}

// TODO: Read and return the memory used by a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::Ram(int pid) {
  string key, units;
  long value;
  string line;
  std::ifstream filestream(kProcDirectory + to_string(pid) + kStatusFilename);

  if (filestream.is_open()) {
    filestream.seekg(10);
    while (std::getline(filestream, line)) {
      std::istringstream linestream(line);
      while (linestream >> key >> value >> units) {
        if (key == "VmSize:") {
          return to_string(value / 1024);
        }
      }
    }
  }
  return string();
}

// TODO: Read and return the user ID associated with a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::Uid(int pid) {
  string line, key, value;
  std::ifstream filestream(kProcDirectory + to_string(pid) + kStatusFilename);
  if (filestream.is_open()) {
    while (std::getline(filestream, line)) {
      std::istringstream linestream(line);
      linestream >> key >> value;
      if (key == "Uid:") return value;
    }
  }
  return string();
}

// TODO: Read and return the user associated with a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::User(int pid) {
  string uid = Uid(pid), userName;
  std::ifstream filestream(kPasswordPath);
  long runningProcesses = 0;
  if (filestream.is_open()) {
    string line;

    while (std::getline(filestream, line)) {
      std::replace(line.begin(), line.end(), ' ', '_');
      std::replace(line.begin(), line.end(), ':', ' ');
      std::istringstream linestream(line);
      std::string pwd;
      std::string currentUid;
      linestream >> userName >> pwd >> currentUid;
      if (currentUid == uid) {
        return userName;
      }
    }
  }
  return string();
}

// TODO: Read and return the uptime of a process
// REMOVE: [[maybe_unused]] once you define the function
long LinuxParser::UpTime(int pid) {
  std::ifstream filestream(kProcDirectory + to_string(pid) + kStatFilename);
  long uptime = 0;
  string str;
  if (filestream.is_open()) {
    for (int i = 0; i < 22; i++) {
      filestream >> str;
    }
    uptime = std::stol(str);
  }
  return uptime / sysconf(_SC_CLK_TCK);
}

std::vector<long> LinuxParser::CpuTimes() {
  std::vector<long> times;
  std::ifstream filestream(kProcDirectory + kStatFilename);
  if (filestream.is_open()) {
    filestream.ignore(5, ' ');  // Skip the 'cpu' prefix.
    for (long time; filestream >> time; times.push_back(time))
      ;
  }
  return times;
}