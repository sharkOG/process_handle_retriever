# Process Handle Retriever

![C++](https://img.shields.io/badge/language-C%2B%2B-blue?style=flat)

## Overview

**Process Handle Retriever** is a lightweight C++ tool designed to locate and retrieve handles of a specific Windows process, making it ideal for tasks like DLL injection and memory manipulation.

---

## Important Information

- **Target Process**: `cs2.exe`
- **Core Functionality**:
  - Retrieves the process ID of `cs2.exe`.
  - Uses `NtQuerySystemInformation` to enumerate system handles.
  - Duplicates handles for further operations.

---

## Scenario

This tool can be utilized for:
- **DLL Injection**: Access and modify target process memory.
- **Memory Editing**: Inspect and manipulate the memory of the target process.
- **Development & Research**: Learn about Windows process management.

---

## Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/ProcessHandleRetriever.git
   cd ProcessHandleRetriever
