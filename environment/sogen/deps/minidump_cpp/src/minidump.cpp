#include "minidump/minidump.hpp"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace minidump {

// memory_segment implementation
std::vector<uint8_t> memory_segment::read(uint64_t virtual_address, size_t read_size,
                                          std::ifstream& file) const {
  if (virtual_address < start_virtual_address || virtual_address >= end_virtual_address()) {
    throw std::runtime_error("Virtual address not in this segment");
  }

  if (virtual_address + read_size > end_virtual_address()) {
    throw std::runtime_error("Read would cross segment boundaries");
  }

  uint64_t offset_in_segment = virtual_address - start_virtual_address;
  uint64_t file_position = start_file_address + offset_in_segment;

  auto current_pos = file.tellg();
  file.seekg(file_position);

  std::vector<uint8_t> data(read_size);
  file.read(reinterpret_cast<char*>(data.data()), read_size);

  file.seekg(current_pos);
  return data;
}

// minidump_file implementation
std::unique_ptr<minidump_file> minidump_file::parse(const std::string& filename) {
  auto minidump = std::unique_ptr<minidump_file>(new minidump_file());
  minidump->filename_ = filename;

  std::ifstream file(filename, std::ios::binary);
  if (!file.is_open()) {
    return nullptr;
  }

  if (!minidump->parse_internal(file)) {
    return nullptr;
  }

  return minidump;
}

std::unique_ptr<minidump_file>
minidump_file::parse_from_buffer(const std::vector<uint8_t>& buffer) {
  // For simplicity, write to temp file and parse
  std::string temp_filename = "/tmp/minidump_temp.dmp";
  std::ofstream temp_file(temp_filename, std::ios::binary);
  temp_file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
  temp_file.close();

  auto result = parse(temp_filename);
  std::remove(temp_filename.c_str());
  return result;
}

bool minidump_file::parse_internal(std::ifstream& file) {
  return parse_header(file) && parse_directories(file) && parse_streams(file);
}

bool minidump_file::parse_header(std::ifstream& file) {
  file.seekg(0);
  file.read(reinterpret_cast<char*>(&header_), sizeof(header_));
  return !file.fail() && header_.is_valid();
}

bool minidump_file::parse_directories(std::ifstream& file) {
  file.seekg(header_.stream_directory_rva);

  directories_.resize(header_.number_of_streams);
  for (uint32_t i = 0; i < header_.number_of_streams; ++i) {
    file.read(reinterpret_cast<char*>(&directories_[i]), sizeof(directory));
    if (file.fail())
      return false;
  }
  return true;
}

bool minidump_file::parse_streams(std::ifstream& file) {
  for (const auto& dir : directories_) {
    file.clear(); // Clear any error flags before parsing each stream

    switch (static_cast<stream_type>(dir.stream_type)) {
    case stream_type::thread_list_stream:
      if (!parse_thread_list_stream(file, dir))
        return false;
      break;
    case stream_type::module_list_stream:
      if (!parse_module_list_stream(file, dir))
        return false;
      break;
    case stream_type::memory64_list_stream:
      if (!parse_memory64_list_stream(file, dir))
        return false;
      break;
    case stream_type::memory_info_list_stream:
      if (!parse_memory_info_list_stream(file, dir))
        return false;
      break;
    case stream_type::system_info_stream:
      if (!parse_system_info_stream(file, dir))
        return false;
      break;
    case stream_type::exception_stream:
      if (!parse_exception_stream(file, dir))
        return false;
      break;
    case stream_type::misc_info_stream:
      if (!parse_misc_info_stream(file, dir))
        return false;
      break;
    case stream_type::handle_data_stream:
      if (!parse_handle_data_stream(file, dir))
        return false;
      break;
    default:
      // Skip unknown streams
      break;
    }
  }
  return true;
}

bool minidump_file::parse_thread_list_stream(std::ifstream& file, const directory& dir) {
  file.seekg(dir.rva);

  uint32_t number_of_threads;
  file.read(reinterpret_cast<char*>(&number_of_threads), sizeof(number_of_threads));
  if (file.fail())
    return false;

  threads_.resize(number_of_threads);
  for (uint32_t i = 0; i < number_of_threads; ++i) {
    file.read(reinterpret_cast<char*>(&threads_[i]), sizeof(thread_info));
    if (file.fail())
      return false;
  }
  return true;
}

bool minidump_file::parse_module_list_stream(std::ifstream& file, const directory& dir) {
  file.seekg(dir.rva);

  uint32_t number_of_modules;
  file.read(reinterpret_cast<char*>(&number_of_modules), sizeof(number_of_modules));
  if (file.fail())
    return false;

  modules_.resize(number_of_modules);
  for (uint32_t i = 0; i < number_of_modules; ++i) {
    file.read(reinterpret_cast<char*>(&modules_[i]), 108); // Size without string
    if (file.fail())
      return false;

    // Read module name
    if (modules_[i].module_name_rva != 0) {
      auto current_pos = file.tellg();
      file.seekg(modules_[i].module_name_rva);

      uint32_t length;
      file.read(reinterpret_cast<char*>(&length), sizeof(length));

      if (!file.fail() && length > 0 && length < 2048) {
        std::vector<uint8_t> name_buffer(length);
        file.read(reinterpret_cast<char*>(name_buffer.data()), length);
        if (!file.fail()) {
          modules_[i].module_name = utils::read_utf16_string(name_buffer.data(), length);
        }
      }
      file.seekg(current_pos);
    }
  }
  return true;
}

bool minidump_file::parse_memory64_list_stream(std::ifstream& file, const directory& dir) {
  file.seekg(dir.rva);

  uint64_t number_of_memory_ranges;
  uint64_t base_rva;

  file.read(reinterpret_cast<char*>(&number_of_memory_ranges), sizeof(number_of_memory_ranges));
  file.read(reinterpret_cast<char*>(&base_rva), sizeof(base_rva));
  if (file.fail())
    return false;

  uint64_t current_rva = base_rva;

  for (uint64_t i = 0; i < number_of_memory_ranges && i < 10000; ++i) {
    uint64_t start_va, size;
    file.read(reinterpret_cast<char*>(&start_va), sizeof(start_va));
    file.read(reinterpret_cast<char*>(&size), sizeof(size));
    if (file.fail())
      break;

    if (size > 0) {
      memory_segments_.emplace_back(start_va, size, current_rva);
      current_rva += size;
    }
  }
  return true;
}

bool minidump_file::parse_memory_info_list_stream(std::ifstream& file, const directory& dir) {
  file.seekg(dir.rva);

  uint32_t size_of_header;
  uint32_t size_of_entry;
  uint64_t number_of_entries;

  file.read(reinterpret_cast<char*>(&size_of_header), sizeof(size_of_header));
  file.read(reinterpret_cast<char*>(&size_of_entry), sizeof(size_of_entry));
  file.read(reinterpret_cast<char*>(&number_of_entries), sizeof(number_of_entries));

  if (file.fail() || size_of_entry != sizeof(memory_info_entry))
    return false;

  for (uint64_t i = 0; i < number_of_entries && i < 10000; ++i) {
    memory_info_entry info;
    file.read(reinterpret_cast<char*>(&info), sizeof(info));
    if (file.fail())
      break;

    memory_regions_.emplace_back(info);
  }
  return true;
}

bool minidump_file::parse_system_info_stream(std::ifstream& file, const directory& dir) {
  file.seekg(dir.rva);
  system_info_ = std::make_unique<system_info>();
  file.read(reinterpret_cast<char*>(system_info_.get()), sizeof(system_info));
  return !file.fail();
}

bool minidump_file::parse_exception_stream(std::ifstream& file, const directory& dir) {
  file.seekg(dir.rva);
  exception_info_ = std::make_unique<exception_info>();
  file.read(reinterpret_cast<char*>(exception_info_.get()), sizeof(exception_info));
  return !file.fail();
}

bool minidump_file::parse_misc_info_stream(std::ifstream& file, const directory& dir) {
  file.seekg(dir.rva);
  misc_info_ = std::make_unique<misc_info>();
  file.read(reinterpret_cast<char*>(misc_info_.get()), sizeof(misc_info));
  return !file.fail();
}

bool minidump_file::parse_handle_data_stream(std::ifstream& file, const directory& dir) {
  file.seekg(dir.rva);

  handle_data_stream_header header;
  file.read(reinterpret_cast<char*>(&header), sizeof(header));
  if (file.fail())
    return false;

  for (uint32_t i = 0; i < header.number_of_descriptors; ++i) {
    handle_descriptor handle;
    file.read(reinterpret_cast<char*>(&handle), 32); // Fixed size for basic descriptor
    if (file.fail())
      break;

    // Read type name if available
    if (handle.type_name_rva != 0) {
      auto current_pos = file.tellg();
      file.seekg(handle.type_name_rva);

      uint32_t length;
      file.read(reinterpret_cast<char*>(&length), sizeof(length));
      if (!file.fail() && length > 0 && length < 2048) {
        std::vector<uint8_t> name_buffer(length);
        file.read(reinterpret_cast<char*>(name_buffer.data()), length);
        if (!file.fail()) {
          handle.type_name = utils::read_utf16_string(name_buffer.data(), length);
        }
      }
      file.seekg(current_pos);
    }

    // Read object name if available
    if (handle.object_name_rva != 0) {
      auto current_pos = file.tellg();
      file.seekg(handle.object_name_rva);

      uint32_t length;
      file.read(reinterpret_cast<char*>(&length), sizeof(length));
      if (!file.fail() && length > 0 && length < 2048) {
        std::vector<uint8_t> name_buffer(length);
        file.read(reinterpret_cast<char*>(name_buffer.data()), length);
        if (!file.fail()) {
          handle.object_name = utils::read_utf16_string(name_buffer.data(), length);
        }
      }
      file.seekg(current_pos);
    }

    handles_.push_back(handle);
  }

  return true;
}

// Print methods with exact Python formatting
void minidump_file::print_all() const {
  std::cout << std::endl;
  std::cout << "# minidump 0.0.21 " << std::endl;
  std::cout << "# Author: redthing1 (based on python minidump)" << std::endl;
  std::cout << std::endl;
  print_threads();
  print_modules();
  print_memory_segments();
  print_memory_regions();
  print_system_info();
  print_exception();
  print_handles();
  print_misc_info();
  print_header();
}

void minidump_file::print_threads() const {
  std::cout << "ThreadList" << std::endl;

  std::vector<std::string> headers = {"ThreadId", "SuspendCount", "PriorityClass", "Priority",
                                      "Teb"};
  std::vector<size_t> widths = {8, 12, 13, 8, 8};

  utils::print_table_header(headers, widths);
  utils::print_table_separator(widths);

  for (const auto& thread : threads_) {
    std::vector<std::string> values = {
        utils::format_hex(thread.thread_id), std::to_string(thread.suspend_count),
        std::to_string(thread.priority_class), std::to_string(thread.priority),
        utils::format_hex(thread.teb)};
    utils::print_table_row(values, widths);
  }
  std::cout << std::endl;
}

void minidump_file::print_modules() const {
  std::cout << "== ModuleList ==" << std::endl;

  std::vector<std::string> headers = {"Module name", "BaseAddress", "Size", "Endaddress",
                                      "Timestamp"};
  std::vector<size_t> widths = {59, 14, 8, 14, 10};

  utils::print_table_header(headers, widths);
  utils::print_table_separator(widths);

  for (const auto& module : modules_) {
    std::vector<std::string> values = {
        module.module_name, utils::format_hex_padded(module.base_of_image, 8),
        utils::format_hex(module.size_of_image), utils::format_hex_padded(module.end_address(), 8),
        utils::format_hex(module.time_date_stamp)};
    utils::print_table_row(values, widths);
  }
  std::cout << std::endl;
}

void minidump_file::print_memory_segments() const {
  std::cout << "== MinidumpMemory64List ==" << std::endl;

  std::vector<std::string> headers = {"VA Start", "RVA", "Size"};
  std::vector<size_t> widths = {14, 8, 8};

  utils::print_table_header(headers, widths);
  utils::print_table_separator(widths);

  for (const auto& segment : memory_segments_) {
    std::vector<std::string> values = {utils::format_hex(segment.start_virtual_address),
                                       utils::format_hex(segment.start_file_address),
                                       utils::format_hex(segment.size)};
    utils::print_table_row(values, widths);
  }
  std::cout << std::endl;
}

void minidump_file::print_memory_regions() const {
  std::cout << "== MinidumpMemoryInfoList ==" << std::endl;

  std::vector<std::string> headers = {"BaseAddress", "AllocationBase", "AllocationProtect",
                                      "RegionSize",  "State",          "Protect",
                                      "Type"};
  std::vector<size_t> widths = {14, 14, 17, 10, 11, 25, 11};

  utils::print_table_header(headers, widths);
  utils::print_table_separator(widths);

  for (const auto& region : memory_regions_) {
    std::vector<std::string> values = {
        utils::format_hex(region.base_address),
        region.allocation_base ? utils::format_hex(region.allocation_base) : "0",
        std::to_string(region.allocation_protect),
        utils::format_hex(region.region_size),
        utils::memory_state_to_string(region.state),
        utils::memory_protection_to_string(region.protect),
        utils::memory_type_to_string(region.type)};
    utils::print_table_row(values, widths);
  }
  std::cout << std::endl;
}

void minidump_file::print_system_info() const {
  if (!system_info_)
    return;

  std::cout << "== System Info ==" << std::endl;
  std::cout << "ProcessorArchitecture PROCESSOR_ARCHITECTURE."
            << utils::processor_architecture_to_string(
                   static_cast<processor_architecture>(system_info_->processor_architecture))
            << std::endl;
  std::cout << "OperatingSystem -guess- " << utils::guess_operating_system(*system_info_)
            << std::endl;
  std::cout << "ProcessorLevel " << system_info_->processor_level << std::endl;
  std::cout << "ProcessorRevision " << utils::format_hex(system_info_->processor_revision)
            << std::endl;
  std::cout << "NumberOfProcessors " << static_cast<int>(system_info_->number_of_processors)
            << std::endl;
  std::cout << "ProductType PRODUCT_TYPE."
            << (system_info_->product_type == 1   ? "VER_NT_WORKSTATION"
                : system_info_->product_type == 2 ? "VER_NT_DOMAIN_CONTROLLER"
                                                  : "VER_NT_SERVER")
            << std::endl;
  std::cout << "MajorVersion " << system_info_->major_version << std::endl;
  std::cout << "MinorVersion " << system_info_->minor_version << std::endl;
  std::cout << "BuildNumber " << system_info_->build_number << std::endl;
  std::cout << "PlatformId PLATFORM_ID."
            << (system_info_->platform_id == 2 ? "VER_PLATFORM_WIN32_NT" : "UNKNOWN") << std::endl;
  std::cout << "CSDVersion: " << std::endl;
  std::cout << "SuiteMask " << system_info_->suite_mask << std::endl;

  // Extract VendorId, VersionInformation, etc. from processor_features like Python does
  uint64_t features0 = system_info_->processor_features[0];
  uint64_t features1 = system_info_->processor_features[1];

  std::cout << "VendorId " << utils::format_hex(features0 & 0xFFFFFFFF) << " "
            << utils::format_hex((features0 >> 32) & 0xFFFFFFFF) << " "
            << utils::format_hex(features1 & 0xFFFFFFFF) << std::endl;
  std::cout << "VersionInformation " << ((features1 >> 32) & 0xFFFFFFFF) << std::endl;
  std::cout << "FeatureInformation " << (features0 & 0xFFFFFFFF) << std::endl;
  std::cout << "AMDExtendedCpuFeatures " << ((features0 >> 32) & 0xFFFFFFFF) << std::endl;
  std::cout << "ProcessorFeatures" << std::endl;
  std::cout << std::endl;
}

void minidump_file::print_exception() const {
  if (!exception_info_)
    return;

  std::cout << "== ExceptionList ==" << std::endl;

  std::vector<std::string> headers = {"ThreadId",         "ExceptionCode",
                                      "ExceptionFlags",   "ExceptionRecord",
                                      "ExceptionAddress", "ExceptionInformation"};
  std::vector<size_t> widths = {10, 31, 14, 15, 16, 19};

  utils::print_table_header(headers, widths);
  utils::print_table_separator(widths);

  std::vector<std::string> values = {
      utils::format_hex(exception_info_->thread_id),
      "ExceptionCode.EXCEPTION_UNKNOWN",
      utils::format_hex(exception_info_->exception_record.exception_flags),
      utils::format_hex(exception_info_->exception_record.exception_record),
      utils::format_hex(exception_info_->exception_record.exception_address),
      "[]"};
  utils::print_table_row(values, widths);
  std::cout << std::endl;
}

void minidump_file::print_misc_info() const {
  if (!misc_info_)
    return;

  std::cout << "== MinidumpMiscInfo ==" << std::endl;
  std::cout << "SizeOfInfo " << misc_info_->size_of_info << std::endl;
  std::cout << "Flags1 " << misc_info_->flags1 << std::endl;
  std::cout << "ProcessId " << misc_info_->process_id << std::endl;
  std::cout << "ProcessCreateTime " << misc_info_->process_create_time << std::endl;
  std::cout << "ProcessUserTime " << misc_info_->process_user_time << std::endl;
  std::cout << "ProcessKernelTime " << misc_info_->process_kernel_time << std::endl;
  std::cout << "ProcessorMaxMhz " << misc_info_->processor_max_mhz << std::endl;
  std::cout << "ProcessorCurrentMhz " << misc_info_->processor_current_mhz << std::endl;
  std::cout << "ProcessorMhzLimit " << misc_info_->processor_mhz_limit << std::endl;
  std::cout << "ProcessorMaxIdleState " << misc_info_->processor_max_idle_state << std::endl;
  std::cout << "ProcessorCurrentIdleState " << misc_info_->processor_current_idle_state
            << std::endl;
  std::cout << std::endl;
}

void minidump_file::print_handles() const {
  if (handles_.empty())
    return;

  std::cout << "== MinidumpHandleDataStream ==" << std::endl;
  std::cout << "== MinidumpHandleDescriptor == " << std::endl;
  for (const auto& handle : handles_) {
    std::cout << "Handle 0x" << std::hex << std::setfill('0') << std::setw(8) << handle.handle
              << " TypeName " << handle.type_name << " ObjectName " << handle.object_name
              << " Attributes " << std::dec << handle.attributes << " GrantedAccess "
              << handle.granted_access << " HandleCount " << handle.handle_count << " PointerCount "
              << handle.pointer_count << std::endl;
  }
  std::cout << std::endl;
}

void minidump_file::print_header() const {
  std::cout << std::endl;
  std::cout << "== MinidumpHeader ==" << std::endl;
  std::cout << "Signature: PMDM" << std::endl;
  std::cout << "Version: " << header_.version << std::endl;
  std::cout << "ImplementationVersion: " << header_.implementation_version << std::endl;
  std::cout << "NumberOfStreams: " << header_.number_of_streams << std::endl;
  std::cout << "StreamDirectoryRva: " << header_.stream_directory_rva << std::endl;
  std::cout << "CheckSum: " << header_.checksum << std::endl;
  std::cout << "Reserved: " << header_.time_date_stamp << std::endl;
  std::cout << "TimeDateStamp: " << static_cast<uint32_t>(header_.flags & 0xFFFFFFFF) << std::endl;
  std::cout << "Flags: " << static_cast<uint32_t>(header_.flags >> 32) << std::endl;
  std::cout << std::endl;
}

std::unique_ptr<minidump_reader> minidump_file::get_reader() {
  return std::make_unique<minidump_reader>(this);
}

// minidump_reader implementation
minidump_reader::minidump_reader(minidump_file* file_ptr)
    : file_(file_ptr), stream_(file_ptr->filename(), std::ios::binary) {
  if (!stream_.is_open()) {
    throw std::runtime_error("Failed to open file for reading");
  }
}

std::vector<uint8_t> minidump_reader::read_memory(uint64_t virtual_address, size_t size) {
  const auto* segment = find_memory_segment(virtual_address);
  if (!segment) {
    throw std::runtime_error("Address not in memory space");
  }
  return segment->read(virtual_address, size, stream_);
}

std::optional<uint64_t> minidump_reader::read_pointer(uint64_t virtual_address) {
  try {
    size_t pointer_size = get_pointer_size();
    auto data = read_memory(virtual_address, pointer_size);

    uint64_t result = 0;
    std::memcpy(&result, data.data(), pointer_size);
    return result;
  } catch (const std::exception&) {
    return std::nullopt;
  }
}

std::string minidump_reader::read_string(uint64_t virtual_address, size_t max_length) {
  try {
    auto data = read_memory(virtual_address, max_length);
    auto null_pos = std::find(data.begin(), data.end(), 0);
    if (null_pos != data.end()) {
      data.erase(null_pos, data.end());
    }
    return std::string(data.begin(), data.end());
  } catch (const std::exception&) {
    return "";
  }
}

const module_info* minidump_reader::find_module_by_address(uint64_t address) const noexcept {
  for (const auto& module : file_->modules()) {
    if (address >= module.base_of_image && address < module.base_of_image + module.size_of_image) {
      return &module;
    }
  }
  return nullptr;
}

const module_info* minidump_reader::find_module_by_name(std::string_view name) const noexcept {
  for (const auto& module : file_->modules()) {
    if (module.module_name.find(name) != std::string::npos) {
      return &module;
    }
  }
  return nullptr;
}

const memory_segment* minidump_reader::find_memory_segment(uint64_t address) const noexcept {
  for (const auto& segment : file_->memory_segments()) {
    if (segment.contains(address)) {
      return &segment;
    }
  }
  return nullptr;
}

processor_architecture minidump_reader::get_architecture() const noexcept {
  if (file_->get_system_info()) {
    return static_cast<processor_architecture>(file_->get_system_info()->processor_architecture);
  }
  return processor_architecture::unknown;
}

bool minidump_reader::is_64bit() const noexcept {
  auto arch = get_architecture();
  return arch == processor_architecture::amd64 || arch == processor_architecture::ia64 ||
         arch == processor_architecture::arm64 || arch == processor_architecture::aarch64;
}

size_t minidump_reader::get_pointer_size() const noexcept { return is_64bit() ? 8 : 4; }

// Utility functions
namespace utils {

std::string processor_architecture_to_string(processor_architecture arch) {
  switch (arch) {
  case processor_architecture::intel:
    return "INTEL";
  case processor_architecture::amd64:
    return "AMD64";
  case processor_architecture::arm:
    return "ARM";
  case processor_architecture::aarch64:
    return "AARCH64";
  case processor_architecture::ia64:
    return "IA64";
  case processor_architecture::arm64:
    return "ARM64";
  default:
    return "UNKNOWN";
  }
}

std::string stream_type_to_string(stream_type type) {
  switch (type) {
  case stream_type::unused_stream:
    return "Unused";
  case stream_type::thread_list_stream:
    return "ThreadList";
  case stream_type::module_list_stream:
    return "ModuleList";
  case stream_type::memory_list_stream:
    return "MemoryList";
  case stream_type::exception_stream:
    return "Exception";
  case stream_type::system_info_stream:
    return "SystemInfo";
  case stream_type::memory64_list_stream:
    return "Memory64List";
  case stream_type::memory_info_list_stream:
    return "MemoryInfoList";
  case stream_type::misc_info_stream:
    return "MiscInfo";
  default:
    return "Unknown";
  }
}

std::string memory_state_to_string(uint32_t state) {
  switch (state) {
  case 0x1000:
    return "MEM_COMMIT";
  case 0x2000:
    return "MEM_RESERVE";
  case 0x10000:
    return "MEM_FREE";
  default:
    return "UNKNOWN";
  }
}

std::string memory_protection_to_string(uint32_t protection) {
  switch (protection) {
  case 0x01:
    return "PAGE_NOACCESS";
  case 0x02:
    return "PAGE_READONLY";
  case 0x04:
    return "PAGE_READWRITE";
  case 0x08:
    return "PAGE_WRITECOPY";
  case 0x10:
    return "PAGE_EXECUTE";
  case 0x20:
    return "PAGE_EXECUTE_READ";
  case 0x40:
    return "PAGE_EXECUTE_READWRITE";
  case 0x80:
    return "PAGE_EXECUTE_WRITECOPY";
  default:
    return "PAGE_UNKNOWN";
  }
}

std::string memory_type_to_string(uint32_t type) {
  switch (type) {
  case 0x1000000:
    return "MEM_IMAGE";
  case 0x40000:
    return "MEM_MAPPED";
  case 0x20000:
    return "MEM_PRIVATE";
  case 0:
    return "N/A";
  default:
    return "UNKNOWN";
  }
}

std::string guess_operating_system(const system_info& sysinfo) {
  if (sysinfo.major_version == 10 && sysinfo.minor_version == 0) {
    return sysinfo.product_type == static_cast<uint8_t>(product_type::ver_nt_workstation)
               ? "Windows 10"
               : "Windows Server 2016";
  } else if (sysinfo.major_version == 6 && sysinfo.minor_version == 3) {
    return sysinfo.product_type == static_cast<uint8_t>(product_type::ver_nt_workstation)
               ? "Windows 8.1"
               : "Windows Server 2012 R2";
  } else if (sysinfo.major_version == 6 && sysinfo.minor_version == 2) {
    return sysinfo.product_type == static_cast<uint8_t>(product_type::ver_nt_workstation)
               ? "Windows 8"
               : "Windows Server 2012";
  } else if (sysinfo.major_version == 6 && sysinfo.minor_version == 1) {
    return sysinfo.product_type == static_cast<uint8_t>(product_type::ver_nt_workstation)
               ? "Windows 7"
               : "Windows Server 2008 R2";
  } else if (sysinfo.major_version == 6 && sysinfo.minor_version == 0) {
    return sysinfo.product_type == static_cast<uint8_t>(product_type::ver_nt_workstation)
               ? "Windows Vista"
               : "Windows Server 2008";
  } else if (sysinfo.major_version == 5 && sysinfo.minor_version == 1) {
    return "Windows XP";
  } else if (sysinfo.major_version == 5 && sysinfo.minor_version == 0) {
    return "Windows 2000";
  }
  return "Unknown";
}

std::string read_utf16_string(const uint8_t* buffer, size_t length) {
  if (!buffer || length == 0)
    return "";

  std::string result;
  for (size_t i = 0; i < length; i += 2) {
    if (i + 1 < length) {
      uint16_t utf16_char = buffer[i] | (buffer[i + 1] << 8);
      if (utf16_char < 128 && utf16_char != 0) {
        result += static_cast<char>(utf16_char);
      }
    }
  }
  return result;
}

std::string format_hex(uint64_t value, bool prefix) {
  std::ostringstream oss;
  if (prefix)
    oss << "0x";
  oss << std::hex << value;
  return oss.str();
}

std::string format_hex_padded(uint64_t value, size_t width) {
  std::ostringstream oss;
  oss << "0x" << std::hex << std::setw(width) << std::setfill('0') << value;
  return oss.str();
}

std::string format_timestamp(uint32_t timestamp) { return std::to_string(timestamp); }

void print_table_header(const std::vector<std::string>& headers,
                        const std::vector<size_t>& widths) {
  for (size_t i = 0; i < headers.size(); ++i) {
    std::cout << std::left << std::setw(widths[i]) << headers[i];
    if (i < headers.size() - 1)
      std::cout << " | ";
  }
  std::cout << std::endl;
}

void print_table_separator(const std::vector<size_t>& widths) {
  size_t total_length = 0;
  for (size_t i = 0; i < widths.size(); ++i) {
    total_length += widths[i];
    if (i < widths.size() - 1)
      total_length += 3; // " | "
  }
  std::cout << std::string(total_length, '-') << std::endl;
}

void print_table_row(const std::vector<std::string>& values, const std::vector<size_t>& widths) {
  for (size_t i = 0; i < values.size() && i < widths.size(); ++i) {
    std::cout << std::left << std::setw(widths[i]) << values[i];
    if (i < values.size() - 1 && i < widths.size() - 1) {
      std::cout << " | ";
    }
  }
  std::cout << std::endl;
}

} // namespace utils

} // namespace minidump