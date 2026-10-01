#include "minidump/minidump.hpp"
#include <iostream>

int main() {
  std::cout << "=== STRUCTURE SIZES ===" << std::endl;
  std::cout << "sizeof(minidump::minidump_header): " << sizeof(minidump::minidump_header)
            << std::endl;
  std::cout << "sizeof(minidump::directory): " << sizeof(minidump::directory) << std::endl;
  std::cout << "sizeof(minidump::thread_info): " << sizeof(minidump::thread_info) << std::endl;
  std::cout << "sizeof(minidump::system_info): " << sizeof(minidump::system_info) << std::endl;
  std::cout << "sizeof(minidump::module_info): " << sizeof(minidump::module_info) << std::endl;
  std::cout << "sizeof(minidump::memory_info_entry): " << sizeof(minidump::memory_info_entry)
            << std::endl;
  std::cout << "sizeof(minidump::exception_info): " << sizeof(minidump::exception_info)
            << std::endl;
  std::cout << "sizeof(minidump::misc_info): " << sizeof(minidump::misc_info) << std::endl;

  std::cout << "\n=== THREAD_INFO FIELD OFFSETS ===" << std::endl;
  minidump::thread_info* t = nullptr;
  std::cout << "thread_id offset: " << (size_t)&(t->thread_id) << std::endl;
  std::cout << "suspend_count offset: " << (size_t)&(t->suspend_count) << std::endl;
  std::cout << "priority_class offset: " << (size_t)&(t->priority_class) << std::endl;
  std::cout << "priority offset: " << (size_t)&(t->priority) << std::endl;
  std::cout << "teb offset: " << (size_t)&(t->teb) << std::endl;

  return 0;
}