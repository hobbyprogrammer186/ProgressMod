# Quick Start

## Prerequisites
- **Compiler:** Requires C++20 or higher.
- **Dependencies:**
    - CMake 3.20+
    - Qt6 (Core, Gui, Widgets)
    - Python3 (Interpreter and Development.Embed)
    - pybind11
    - capstone
    - libelf

Source Code File Structure:
```bash
root
|---include
    |------definations.h  # Global Header
    |------engine.h       # Header Of Engine
    |------modManager.h   # Header Of Mod Manager
|---src
    |--main.cpp           # Main Program Of ProgressMod
    |--engine.cpp         # ProgressMod Engine
    |--modManager.cpp     # Mod Manager
```
## How To Build
```bash
cmake -B build
cd build
make -j $(nproc)
```
Warning: Test In VM Because ProgressMod Is Alpha Stage