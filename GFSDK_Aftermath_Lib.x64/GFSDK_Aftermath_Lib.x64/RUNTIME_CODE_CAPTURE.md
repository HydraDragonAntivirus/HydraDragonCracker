# Runtime Code Capture - Actual C++ Code Extraction

## Overview

The enhanced proxy DLL now captures **the actual executing code** from the EXE at runtime. This includes:
- **Raw machine code bytes** from memory
- **Disassembled assembly instructions**
- **Function code dumps** with hex representation
- **Complete function implementations** as they exist in memory

## What Gets Captured

### 1. **Actual Code Bytes**
For every EXE function that calls GFSDK:
- Reads the actual memory at the function address
- Captures up to 256 bytes of machine code
- Stores raw bytes in hex format

### 2. **Disassembly**
- Decodes x64 instructions from the captured bytes
- Shows assembly mnemonics (MOV, CALL, JMP, RET, etc.)
- Displays instruction addresses and opcodes
- Identifies common instruction patterns

### 3. **Complete Code Dumps**
Each function's code is dumped with:
- Memory address where code is located
- Hex dump of all bytes
- Disassembled instructions
- Function boundaries (detected by RET instructions)

## How It Works

### Memory Reading
```cpp
// Reads process memory directly (we're in the same process)
bool ReadMemory(DWORD64 address, void* buffer, size_t size)
```

### Code Capture
```cpp
// Captures function code at runtime
CodeDump CaptureFunctionCode(DWORD64 address, size_t maxSize = 256)
```

### Disassembly
```cpp
// Decodes x64 instructions
std::string DisassembleCode(const unsigned char* code, size_t size, DWORD64 baseAddr)
```

## Example Output

```
Function: GraphicsInit
  Address: 0x7FF6A1B34520
  Offset: 0x34520
  Source: renderer.cpp:234
  Call Count: 1

  === ACTUAL CODE (Disassembly) ===
  0x7FF6A1B34520: 55 push rbp
  0x7FF6A1B34521: 48 8B ... mov [reg], [reg]
  0x7FF6A1B34524: 48 89 ... mov [reg], [reg]
  0x7FF6A1B34527: 48 83 ... add/sub/cmp [reg], imm8
  0x7FF6A1B3452A: E8 ... call rel32
  0x7FF6A1B3452F: 48 8B ... mov [reg], [reg]
  0x7FF6A1B34532: C3 ret

  === CODE BYTES (Hex Dump) ===
  Address: 0x7FF6A1B34520
  Size: 256 bytes
  Hex: 55 48 8B EC 48 83 EC 20 48 89 5C 24 10 48 89 74
       24 18 48 89 7C 24 20 4C 89 64 24 28 4C 89 6C 24
       30 4C 89 74 24 38 4C 89 7C 24 40 48 8B 05 ... 
```

## Technical Details

### Instruction Decoding
The disassembler recognizes:
- **REX prefixes** (0x48) for 64-bit operations
- **CALL instructions** (0xE8, 0xFF)
- **JMP instructions** (0xE9, 0xFF)
- **RET instructions** (0xC3) - function end marker
- **MOV operations** (0x89, 0x8B)
- **PUSH/POP** (0x50-0x5F, 0x55, 0x5D)
- **Arithmetic** (0x83 for ADD/SUB/CMP)

### Memory Protection
- Checks memory protection flags before reading
- Only reads from executable/readable pages
- Handles page boundaries safely
- Validates memory access

### Code Size Detection
- Captures up to 256 bytes per function
- Stops at RET instruction (function end)
- Handles incomplete instructions gracefully
- Limits capture to prevent buffer overflows

## What You Can Do With This

### 1. **Reverse Engineering**
- See the actual machine code of EXE functions
- Understand how functions are implemented
- Identify compiler optimizations
- Map code structure

### 2. **Code Analysis**
- Analyze instruction sequences
- Identify function prologues/epilogues
- Find calling conventions
- Detect code patterns

### 3. **Memory Mapping**
- Get exact byte sequences
- Calculate function sizes
- Map code sections
- Identify function boundaries

### 4. **Static Analysis**
- Export code to IDA Pro / Ghidra
- Use addresses for breakpoints
- Map to source code (if PDB available)
- Reconstruct function logic

## Output Format

The code is saved in `EXE_SOURCE_CODE_MAP.txt` with:
- Function name and address
- Complete hex dump of code bytes
- Disassembled instructions
- Instruction addresses

## Limitations

1. **Basic Disassembler**: Simple decoder, not full-featured
   - For complete disassembly, use IDA Pro or Ghidra with the addresses
   
2. **Code Size**: Limited to 256 bytes per function
   - Can be increased in code if needed
   
3. **Instruction Decoding**: Recognizes common patterns
   - Complex instructions may show as "unknown"
   - Full decoding requires professional disassembler

4. **Context**: Code captured at function entry
   - Dynamic behavior not captured
   - Only static code structure

## Advanced Usage

### Exporting to IDA Pro
1. Get function address from map
2. Load EXE in IDA Pro
3. Jump to address: `G` key, enter address
4. Code will match the captured bytes

### Using with Ghidra
1. Import EXE into Ghidra
2. Use addresses from map to navigate
3. Compare with captured disassembly
4. Verify function boundaries

### Building Function Database
Parse the map file to:
- Extract all function addresses
- Build address → function name mapping
- Create code signature database
- Map function relationships

## Future Enhancements

Possible additions:
- Full x64 disassembler (Capstone integration)
- Function size detection
- Code pattern recognition
- Export to IDA script format
- Binary code dumps (.bin files)
- Instruction flow graphs

---

**This feature captures the actual C++ code as it exists in memory at runtime, giving you the real machine code implementation of every EXE function that interacts with GFSDK Aftermath.**

