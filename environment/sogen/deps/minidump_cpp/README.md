# minidump_cpp

a c++ minidump parser. this is a port of the [python minidump library](https://github.com/skelsec/minidump).

this is a portable c++17 library with full feature parity to the original.

## features

stream types:
- Thread List (`ThreadListStream`)
- Module List (`ModuleListStream`) 
- Memory64 List (`Memory64ListStream`)
- Memory Info List (`MemoryInfoListStream`)
- System Info (`SystemInfoStream`)
- Exception (`ExceptionStream`)
- Handle Data (`HandleDataStream`)
- Misc Info (`MiscInfoStream`)

## quickstart

in your `CMakeLists.txt`:
```cmake
add_subdirectory(external/minidump)
target_link_libraries(your_target PRIVATE minidump::minidump)
```

the library automatically disables examples and tests when included as a subdirectory.

using cmake package:
```cmake
find_package(minidump REQUIRED)
target_link_libraries(your_target PRIVATE minidump::minidump)
```

## usage

```cpp
#include "minidump/minidump.hpp"

// Parse a minidump file
auto dump = minidump::minidump_file::parse("crash.dmp");
if (!dump) {
    std::cerr << "Failed to parse minidump file\n";
    return -1;
}

// Access parsed data
const auto& threads = dump->threads();
const auto& modules = dump->modules();
const auto& memory_segments = dump->memory_segments();

// Read memory directly
auto reader = dump->get_reader();
try {
    auto data = reader->read_memory(0x140000000, 256);
    auto pointer = reader->read_pointer(0x140001000);
    auto string = reader->read_string(0x140002000);
} catch (const std::exception& e) {
    std::cerr << "Memory read failed: " << e.what() << "\n";
}

// Find modules and memory regions
const auto* module = reader->find_module_by_name("kernel32.dll");
const auto* segment = reader->find_memory_segment(0x140000000);
```

## api reference

### core classes

#### `minidump::minidump_file`

Main parser class for minidump files.

```cpp
// Static factory methods
static std::unique_ptr<minidump_file> parse(const std::string& filename);
static std::unique_ptr<minidump_file> parse_from_buffer(const std::vector<uint8_t>& buffer);

// Data accessors
const minidump_header& header() const noexcept;
const std::vector<thread_info>& threads() const noexcept;
const std::vector<module_info>& modules() const noexcept;
const std::vector<memory_segment>& memory_segments() const noexcept;
const std::vector<memory_region>& memory_regions() const noexcept;
const system_info* get_system_info() const noexcept;
const exception_info* get_exception_info() const noexcept;

// Create memory reader
std::unique_ptr<minidump_reader> get_reader();
```

#### `minidump::minidump_reader`

Memory access operations on the minidump.

```cpp
// Memory operations
std::vector<uint8_t> read_memory(uint64_t virtual_address, size_t size);
std::optional<uint64_t> read_pointer(uint64_t virtual_address);
std::string read_string(uint64_t virtual_address, size_t max_length = 1024);

// Lookup operations
const module_info* find_module_by_address(uint64_t address) const noexcept;
const module_info* find_module_by_name(std::string_view name) const noexcept;
const memory_segment* find_memory_segment(uint64_t address) const noexcept;

// Architecture info
processor_architecture get_architecture() const noexcept;
bool is_64bit() const noexcept;
size_t get_pointer_size() const noexcept;
```

### data structures

all structures use snake_case naming and are defined in the `minidump` namespace:

- `minidump_header` - File header information
- `thread_info` - Thread details (ID, TEB, priority, etc.)
- `module_info` - Loaded module information
- `memory_segment` - Memory region data
- `memory_region` - Virtual memory layout
- `system_info` - System and processor information
- `exception_info` - Exception details
- `handle_descriptor` - System handle information

## acknowledgments

- compatible with and inspired by the [Python minidump library](https://github.com/skelsec/minidump)
- follows Windows [minidump](https://learn.microsoft.com/en-us/windows/win32/debug/minidump-files) format specification
