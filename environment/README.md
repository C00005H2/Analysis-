# Extracted analysis environment

This directory contains the files needed to use the provisioned reverse-analysis environment:

- `sogen/`: Sogen source and initialized dependencies
- `bin/`: Python environment executables, CMake and Ninja
- `lib/`: installed Python packages and native libraries
- `Include/` and `pyconfig.h`: CPython development headers

Documentation, CI files, test-only sources, and the CPython source tree not needed by the headers/runtime were removed.
