#pragma once

#include <cstdint>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace minidump {

// Enumerations matching Windows minidump format
enum class processor_architecture : uint16_t {
  intel = 0,
  mips = 1,
  alpha = 2,
  ppc = 3,
  shx = 4,
  arm = 5,
  ia64 = 6,
  alpha64 = 7,
  msil = 8,
  amd64 = 9,
  ia32_on_win64 = 10,
  neutral = 11,
  arm64 = 12,
  arm32_on_win64 = 13,
  ia32_on_arm64 = 14,
  aarch64 = 15,
  unknown = 0xFFFF
};

enum class stream_type : uint32_t {
  unused_stream = 0,
  reserved_stream0 = 1,
  reserved_stream1 = 2,
  thread_list_stream = 3,
  module_list_stream = 4,
  memory_list_stream = 5,
  exception_stream = 6,
  system_info_stream = 7,
  thread_ex_list_stream = 8,
  memory64_list_stream = 9,
  comment_stream_a = 10,
  comment_stream_w = 11,
  handle_data_stream = 12,
  function_table_stream = 13,
  unloaded_module_list_stream = 14,
  misc_info_stream = 15,
  memory_info_list_stream = 16,
  thread_info_list_stream = 17,
  handle_operation_list_stream = 18,
  token_stream = 19,
  javascript_data_stream = 20,
  system_memory_info_stream = 21,
  process_vm_counters_stream = 22,
  ipt_trace_stream = 23,
  thread_names_stream = 24,
  last_reserved_stream = 0x0000FFFF
};

enum class product_type : uint8_t {
  ver_nt_workstation = 1,
  ver_nt_domain_controller = 2,
  ver_nt_server = 3
};

// Core structures using snake_case
struct minidump_header {
  static constexpr uint32_t expected_signature = 0x504D444D; // 'MDMP'

  uint32_t signature;
  uint16_t version;
  uint16_t implementation_version;
  uint32_t number_of_streams;
  uint32_t stream_directory_rva;
  uint32_t checksum;
  uint32_t time_date_stamp;
  uint64_t flags;

  [[nodiscard]] bool is_valid() const noexcept {
    return signature == expected_signature && number_of_streams > 0;
  }
};

struct directory {
  uint32_t stream_type;
  uint32_t data_size;
  uint32_t rva;
};

struct system_info {
  uint16_t processor_architecture;
  uint16_t processor_level;
  uint16_t processor_revision;
  uint8_t number_of_processors;
  uint8_t product_type;
  uint32_t major_version;
  uint32_t minor_version;
  uint32_t build_number;
  uint32_t platform_id;
  uint32_t csd_version_rva;
  uint16_t suite_mask;
  uint16_t reserved2;
  uint64_t processor_features[2];
};

struct thread_info {
  uint32_t thread_id;
  uint32_t suspend_count;
  uint32_t priority_class;
  uint32_t priority;
  uint64_t teb;
  // Stack: MINIDUMP_MEMORY_DESCRIPTOR (16 bytes)
  uint64_t stack_start_of_memory_range;
  uint32_t stack_data_size;
  uint32_t stack_rva;
  // ThreadContext: MINIDUMP_LOCATION_DESCRIPTOR (8 bytes)
  uint32_t context_data_size;
  uint32_t context_rva;
};

struct module_info {
  uint64_t base_of_image;
  uint32_t size_of_image;
  uint32_t checksum;
  uint32_t time_date_stamp;
  uint32_t module_name_rva;
  uint64_t version_info[13]; // VS_FIXEDFILEINFO equivalent
  uint32_t cv_record_rva;
  uint32_t cv_record_size;
  uint32_t misc_record_rva;
  uint32_t misc_record_size;
  uint64_t reserved0;
  uint64_t reserved1;

  std::string module_name;

  [[nodiscard]] uint64_t end_address() const noexcept { return base_of_image + size_of_image; }
};

struct memory_descriptor {
  uint64_t start_virtual_address;
  uint32_t data_size;
  uint32_t rva;
};

struct memory_segment {
  uint64_t start_virtual_address;
  uint64_t size;
  uint64_t start_file_address;

  memory_segment(uint64_t start_va, uint64_t segment_size, uint64_t start_fa)
      : start_virtual_address(start_va), size(segment_size), start_file_address(start_fa) {}

  [[nodiscard]] uint64_t end_virtual_address() const noexcept {
    return start_virtual_address + size;
  }

  [[nodiscard]] bool contains(uint64_t address) const noexcept {
    return address >= start_virtual_address && address < end_virtual_address();
  }

  std::vector<uint8_t> read(uint64_t virtual_address, size_t read_size, std::ifstream& file) const;
};

struct memory_info_entry {
  uint64_t base_address;
  uint64_t allocation_base;
  uint32_t allocation_protect;
  uint32_t __alignment1;
  uint64_t region_size;
  uint32_t state;
  uint32_t protect;
  uint32_t type;
  uint32_t __alignment2;
};

struct memory_region {
  uint64_t base_address;
  uint64_t allocation_base;
  uint32_t allocation_protect;
  uint64_t region_size;
  uint32_t state;
  uint32_t protect;
  uint32_t type;

  explicit memory_region(const memory_info_entry& info)
      : base_address(info.base_address), allocation_base(info.allocation_base),
        allocation_protect(info.allocation_protect), region_size(info.region_size),
        state(info.state), protect(info.protect), type(info.type) {}
};

struct exception_info {
  uint32_t thread_id;
  uint32_t __alignment;
  struct {
    uint32_t exception_code;
    uint32_t exception_flags;
    uint64_t exception_record;
    uint64_t exception_address;
    uint32_t number_parameters;
    uint32_t __alignment;
    uint64_t exception_information[15];
  } exception_record;
  uint32_t context_rva;
  uint32_t context_size;
};

struct misc_info {
  uint32_t size_of_info;
  uint32_t flags1;
  uint32_t process_id;
  uint32_t process_create_time;
  uint32_t process_user_time;
  uint32_t process_kernel_time;
  uint32_t processor_max_mhz;
  uint32_t processor_current_mhz;
  uint32_t processor_mhz_limit;
  uint32_t processor_max_idle_state;
  uint32_t processor_current_idle_state;
};

struct handle_data_stream_header {
  uint32_t size_of_header;
  uint32_t size_of_descriptor;
  uint32_t number_of_descriptors;
  uint32_t reserved;
};

struct handle_descriptor {
  uint64_t handle;
  uint32_t type_name_rva;
  uint32_t object_name_rva;
  uint32_t attributes;
  uint32_t granted_access;
  uint32_t handle_count;
  uint32_t pointer_count;

  std::string type_name;
  std::string object_name;
};

// Forward declarations
class minidump_reader;

// Main minidump_file class
class minidump_file {
public:
  static std::unique_ptr<minidump_file> parse(const std::string& filename);
  static std::unique_ptr<minidump_file> parse_from_buffer(const std::vector<uint8_t>& buffer);

  // Accessors
  [[nodiscard]] const minidump_header& header() const noexcept { return header_; }
  [[nodiscard]] const std::vector<thread_info>& threads() const noexcept { return threads_; }
  [[nodiscard]] const std::vector<module_info>& modules() const noexcept { return modules_; }
  [[nodiscard]] const std::vector<memory_segment>& memory_segments() const noexcept {
    return memory_segments_;
  }
  [[nodiscard]] const std::vector<memory_region>& memory_regions() const noexcept {
    return memory_regions_;
  }
  [[nodiscard]] const system_info* get_system_info() const noexcept { return system_info_.get(); }
  [[nodiscard]] const exception_info* get_exception_info() const noexcept {
    return exception_info_.get();
  }
  [[nodiscard]] const misc_info* get_misc_info() const noexcept { return misc_info_.get(); }
  [[nodiscard]] const std::vector<handle_descriptor>& handles() const noexcept { return handles_; }

  // Output methods (Python-compatible)
  void print_all() const;
  void print_threads() const;
  void print_modules() const;
  void print_memory_segments() const;
  void print_memory_regions() const;
  void print_system_info() const;
  void print_exception() const;
  void print_misc_info() const;
  void print_handles() const;
  void print_header() const;

  // Create reader for memory access
  std::unique_ptr<minidump_reader> get_reader();

  // Accessor for filename (needed by reader)
  [[nodiscard]] const std::string& filename() const noexcept { return filename_; }

private:
  minidump_file() = default;

  bool parse_internal(std::ifstream& file);
  bool parse_header(std::ifstream& file);
  bool parse_directories(std::ifstream& file);
  bool parse_streams(std::ifstream& file);
  bool parse_thread_list_stream(std::ifstream& file, const directory& dir);
  bool parse_module_list_stream(std::ifstream& file, const directory& dir);
  bool parse_memory64_list_stream(std::ifstream& file, const directory& dir);
  bool parse_memory_info_list_stream(std::ifstream& file, const directory& dir);
  bool parse_system_info_stream(std::ifstream& file, const directory& dir);
  bool parse_exception_stream(std::ifstream& file, const directory& dir);
  bool parse_misc_info_stream(std::ifstream& file, const directory& dir);
  bool parse_handle_data_stream(std::ifstream& file, const directory& dir);

  std::string filename_;
  minidump_header header_{};
  std::vector<directory> directories_;
  std::vector<thread_info> threads_;
  std::vector<module_info> modules_;
  std::vector<memory_segment> memory_segments_;
  std::vector<memory_region> memory_regions_;
  std::unique_ptr<system_info> system_info_;
  std::unique_ptr<exception_info> exception_info_;
  std::unique_ptr<misc_info> misc_info_;
  std::vector<handle_descriptor> handles_;
};

// minidump_reader for memory access operations
class minidump_reader {
public:
  explicit minidump_reader(minidump_file* file_ptr);

  // Memory reading operations
  std::vector<uint8_t> read_memory(uint64_t virtual_address, size_t size);
  std::optional<uint64_t> read_pointer(uint64_t virtual_address);
  std::string read_string(uint64_t virtual_address, size_t max_length = 1024);

  // Lookup operations
  [[nodiscard]] const module_info* find_module_by_address(uint64_t address) const noexcept;
  [[nodiscard]] const module_info* find_module_by_name(std::string_view name) const noexcept;
  [[nodiscard]] const memory_segment* find_memory_segment(uint64_t address) const noexcept;

  // Architecture information
  [[nodiscard]] processor_architecture get_architecture() const noexcept;
  [[nodiscard]] bool is_64bit() const noexcept;
  [[nodiscard]] size_t get_pointer_size() const noexcept;

private:
  minidump_file* file_;
  std::ifstream stream_;
};

// Utility functions
namespace utils {
std::string processor_architecture_to_string(processor_architecture arch);
std::string stream_type_to_string(stream_type type);
std::string memory_state_to_string(uint32_t state);
std::string memory_protection_to_string(uint32_t protection);
std::string memory_type_to_string(uint32_t type);
std::string guess_operating_system(const system_info& sysinfo);
std::string read_utf16_string(const uint8_t* buffer, size_t length);
std::string format_hex(uint64_t value, bool prefix = true);
std::string format_hex_padded(uint64_t value, size_t width);
std::string format_timestamp(uint32_t timestamp);

// Table formatting (Python-compatible)
void print_table_header(const std::vector<std::string>& headers, const std::vector<size_t>& widths);
void print_table_separator(const std::vector<size_t>& widths);
void print_table_row(const std::vector<std::string>& values, const std::vector<size_t>& widths);
} // namespace utils

} // namespace minidump