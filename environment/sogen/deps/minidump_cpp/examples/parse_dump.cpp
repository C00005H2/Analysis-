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

  dump->print_all();

  return 0;
}