#include "minidump/minidump.hpp"
#include <iostream>

int main(int argc, char* argv[]) {
  if (argc != 2) {
    std::cout << "Usage: " << argv[0] << " <minidump_file>" << std::endl;
    return 1;
  }

  std::string filename = argv[1];

  auto dump = minidump::minidump_file::parse(filename);
  if (!dump) {
    std::cerr << "Failed to parse minidump file: " << filename << std::endl;
    return 1;
  }

  // Debug information
  std::cout << "=== DEBUG INFO ===" << std::endl;
  std::cout << "Header signature: 0x" << std::hex << dump->header().signature << std::dec
            << std::endl;
  std::cout << "Number of streams: " << dump->header().number_of_streams << std::endl;
  std::cout << "Stream directory RVA: 0x" << std::hex << dump->header().stream_directory_rva
            << std::dec << std::endl;
  std::cout << "Threads parsed: " << dump->threads().size() << std::endl;
  std::cout << "Modules parsed: " << dump->modules().size() << std::endl;
  std::cout << "Memory segments: " << dump->memory_segments().size() << std::endl;
  std::cout << "Memory regions: " << dump->memory_regions().size() << std::endl;

  std::cout << "\n=== THREAD DETAILS ===" << std::endl;
  for (size_t i = 0; i < dump->threads().size(); ++i) {
    const auto& t = dump->threads()[i];
    std::cout << "Thread " << i << ": ID=0x" << std::hex << t.thread_id
              << " SuspendCount=" << std::dec << t.suspend_count
              << " PriorityClass=" << t.priority_class << " Priority=" << t.priority << " TEB=0x"
              << std::hex << t.teb << std::dec << std::endl;
  }

  std::cout << "\n=== MODULE DETAILS ===" << std::endl;
  for (size_t i = 0; i < std::min(size_t(5), dump->modules().size()); ++i) {
    const auto& m = dump->modules()[i];
    std::cout << "Module " << i << ": Base=0x" << std::hex << m.base_of_image << " Size=0x"
              << m.size_of_image << " Name=\"" << m.module_name << "\"" << std::dec << std::endl;
  }

  return 0;
}