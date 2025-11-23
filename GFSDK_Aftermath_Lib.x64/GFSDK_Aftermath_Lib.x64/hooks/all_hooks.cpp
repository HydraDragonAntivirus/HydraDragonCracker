#include <windows.h>
#include "aftermath_hooks.h"
// ===================================================================================
// ALL HOOKS GENERATED AUTOMATICALLY
// ===================================================================================

// Original function pointer for GFSDK_Aftermath_DX11_CreateContextHandle
typedef void* (*GFSDK_Aftermath_DX11_CreateContextHandle_t)(...);
static GFSDK_Aftermath_DX11_CreateContextHandle_t orig_GFSDK_Aftermath_DX11_CreateContextHandle = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_DX11_CreateContextHandle(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_DX11_CreateContextHandle", 2);
    if (!orig_GFSDK_Aftermath_DX11_CreateContextHandle && g_origDll) {
        orig_GFSDK_Aftermath_DX11_CreateContextHandle = (GFSDK_Aftermath_DX11_CreateContextHandle_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_DX11_CreateContextHandle");
    }
    if (!orig_GFSDK_Aftermath_DX11_CreateContextHandle) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_DX11_CreateContextHandle not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_DX11_CreateContextHandle();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_DX11_CreateContextHandle -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_DX11_Initialize
typedef void* (*GFSDK_Aftermath_DX11_Initialize_t)(...);
static GFSDK_Aftermath_DX11_Initialize_t orig_GFSDK_Aftermath_DX11_Initialize = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_DX11_Initialize(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_DX11_Initialize", 2);
    if (!orig_GFSDK_Aftermath_DX11_Initialize && g_origDll) {
        orig_GFSDK_Aftermath_DX11_Initialize = (GFSDK_Aftermath_DX11_Initialize_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_DX11_Initialize");
    }
    if (!orig_GFSDK_Aftermath_DX11_Initialize) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_DX11_Initialize not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_DX11_Initialize();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_DX11_Initialize -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_DX12_CreateContextHandle
typedef void* (*GFSDK_Aftermath_DX12_CreateContextHandle_t)(...);
static GFSDK_Aftermath_DX12_CreateContextHandle_t orig_GFSDK_Aftermath_DX12_CreateContextHandle = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_DX12_CreateContextHandle(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_DX12_CreateContextHandle", 2);
    if (!orig_GFSDK_Aftermath_DX12_CreateContextHandle && g_origDll) {
        orig_GFSDK_Aftermath_DX12_CreateContextHandle = (GFSDK_Aftermath_DX12_CreateContextHandle_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_DX12_CreateContextHandle");
    }
    if (!orig_GFSDK_Aftermath_DX12_CreateContextHandle) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_DX12_CreateContextHandle not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_DX12_CreateContextHandle();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_DX12_CreateContextHandle -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_DX12_Initialize
typedef void* (*GFSDK_Aftermath_DX12_Initialize_t)(...);
static GFSDK_Aftermath_DX12_Initialize_t orig_GFSDK_Aftermath_DX12_Initialize = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_DX12_Initialize(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_DX12_Initialize", 2);
    if (!orig_GFSDK_Aftermath_DX12_Initialize && g_origDll) {
        orig_GFSDK_Aftermath_DX12_Initialize = (GFSDK_Aftermath_DX12_Initialize_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_DX12_Initialize");
    }
    if (!orig_GFSDK_Aftermath_DX12_Initialize) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_DX12_Initialize not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_DX12_Initialize();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_DX12_Initialize -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_DX12_RegisterResource
typedef void* (*GFSDK_Aftermath_DX12_RegisterResource_t)(...);
static GFSDK_Aftermath_DX12_RegisterResource_t orig_GFSDK_Aftermath_DX12_RegisterResource = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_DX12_RegisterResource(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_DX12_RegisterResource", 2);
    if (!orig_GFSDK_Aftermath_DX12_RegisterResource && g_origDll) {
        orig_GFSDK_Aftermath_DX12_RegisterResource = (GFSDK_Aftermath_DX12_RegisterResource_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_DX12_RegisterResource");
    }
    if (!orig_GFSDK_Aftermath_DX12_RegisterResource) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_DX12_RegisterResource not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_DX12_RegisterResource();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_DX12_RegisterResource -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_DX12_UnregisterResource
typedef void* (*GFSDK_Aftermath_DX12_UnregisterResource_t)(...);
static GFSDK_Aftermath_DX12_UnregisterResource_t orig_GFSDK_Aftermath_DX12_UnregisterResource = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_DX12_UnregisterResource(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_DX12_UnregisterResource", 2);
    if (!orig_GFSDK_Aftermath_DX12_UnregisterResource && g_origDll) {
        orig_GFSDK_Aftermath_DX12_UnregisterResource = (GFSDK_Aftermath_DX12_UnregisterResource_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_DX12_UnregisterResource");
    }
    if (!orig_GFSDK_Aftermath_DX12_UnregisterResource) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_DX12_UnregisterResource not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_DX12_UnregisterResource();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_DX12_UnregisterResource -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_DisableGpuCrashDumps
typedef void* (*GFSDK_Aftermath_DisableGpuCrashDumps_t)(...);
static GFSDK_Aftermath_DisableGpuCrashDumps_t orig_GFSDK_Aftermath_DisableGpuCrashDumps = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_DisableGpuCrashDumps(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_DisableGpuCrashDumps", 2);
    if (!orig_GFSDK_Aftermath_DisableGpuCrashDumps && g_origDll) {
        orig_GFSDK_Aftermath_DisableGpuCrashDumps = (GFSDK_Aftermath_DisableGpuCrashDumps_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_DisableGpuCrashDumps");
    }
    if (!orig_GFSDK_Aftermath_DisableGpuCrashDumps) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_DisableGpuCrashDumps not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_DisableGpuCrashDumps();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_DisableGpuCrashDumps -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_EnableGpuCrashDumps
typedef void* (*GFSDK_Aftermath_EnableGpuCrashDumps_t)(...);
static GFSDK_Aftermath_EnableGpuCrashDumps_t orig_GFSDK_Aftermath_EnableGpuCrashDumps = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_EnableGpuCrashDumps(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_EnableGpuCrashDumps", 2);
    if (!orig_GFSDK_Aftermath_EnableGpuCrashDumps && g_origDll) {
        orig_GFSDK_Aftermath_EnableGpuCrashDumps = (GFSDK_Aftermath_EnableGpuCrashDumps_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_EnableGpuCrashDumps");
    }
    if (!orig_GFSDK_Aftermath_EnableGpuCrashDumps) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_EnableGpuCrashDumps not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_EnableGpuCrashDumps();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_EnableGpuCrashDumps -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_GetContextError
typedef void* (*GFSDK_Aftermath_GetContextError_t)(...);
static GFSDK_Aftermath_GetContextError_t orig_GFSDK_Aftermath_GetContextError = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_GetContextError(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_GetContextError", 2);
    if (!orig_GFSDK_Aftermath_GetContextError && g_origDll) {
        orig_GFSDK_Aftermath_GetContextError = (GFSDK_Aftermath_GetContextError_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_GetContextError");
    }
    if (!orig_GFSDK_Aftermath_GetContextError) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_GetContextError not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_GetContextError();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_GetContextError -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_GetData
typedef void* (*GFSDK_Aftermath_GetData_t)(...);
static GFSDK_Aftermath_GetData_t orig_GFSDK_Aftermath_GetData = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_GetData(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_GetData", 2);
    if (!orig_GFSDK_Aftermath_GetData && g_origDll) {
        orig_GFSDK_Aftermath_GetData = (GFSDK_Aftermath_GetData_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_GetData");
    }
    if (!orig_GFSDK_Aftermath_GetData) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_GetData not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_GetData();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_GetData -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_GetDeviceStatus
typedef void* (*GFSDK_Aftermath_GetDeviceStatus_t)(...);
static GFSDK_Aftermath_GetDeviceStatus_t orig_GFSDK_Aftermath_GetDeviceStatus = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_GetDeviceStatus(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_GetDeviceStatus", 2);
    if (!orig_GFSDK_Aftermath_GetDeviceStatus && g_origDll) {
        orig_GFSDK_Aftermath_GetDeviceStatus = (GFSDK_Aftermath_GetDeviceStatus_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_GetDeviceStatus");
    }
    if (!orig_GFSDK_Aftermath_GetDeviceStatus) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_GetDeviceStatus not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_GetDeviceStatus();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_GetDeviceStatus -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_GetPageFaultInformation
typedef void* (*GFSDK_Aftermath_GetPageFaultInformation_t)(...);
static GFSDK_Aftermath_GetPageFaultInformation_t orig_GFSDK_Aftermath_GetPageFaultInformation = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_GetPageFaultInformation(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_GetPageFaultInformation", 2);
    if (!orig_GFSDK_Aftermath_GetPageFaultInformation && g_origDll) {
        orig_GFSDK_Aftermath_GetPageFaultInformation = (GFSDK_Aftermath_GetPageFaultInformation_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_GetPageFaultInformation");
    }
    if (!orig_GFSDK_Aftermath_GetPageFaultInformation) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_GetPageFaultInformation not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_GetPageFaultInformation();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_GetPageFaultInformation -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_GetShaderDebugInfoIdentifier
typedef void* (*GFSDK_Aftermath_GetShaderDebugInfoIdentifier_t)(...);
static GFSDK_Aftermath_GetShaderDebugInfoIdentifier_t orig_GFSDK_Aftermath_GetShaderDebugInfoIdentifier = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_GetShaderDebugInfoIdentifier(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_GetShaderDebugInfoIdentifier", 2);
    if (!orig_GFSDK_Aftermath_GetShaderDebugInfoIdentifier && g_origDll) {
        orig_GFSDK_Aftermath_GetShaderDebugInfoIdentifier = (GFSDK_Aftermath_GetShaderDebugInfoIdentifier_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_GetShaderDebugInfoIdentifier");
    }
    if (!orig_GFSDK_Aftermath_GetShaderDebugInfoIdentifier) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_GetShaderDebugInfoIdentifier not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_GetShaderDebugInfoIdentifier();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_GetShaderDebugInfoIdentifier -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_GetShaderDebugName
typedef void* (*GFSDK_Aftermath_GetShaderDebugName_t)(...);
static GFSDK_Aftermath_GetShaderDebugName_t orig_GFSDK_Aftermath_GetShaderDebugName = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_GetShaderDebugName(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_GetShaderDebugName", 2);
    if (!orig_GFSDK_Aftermath_GetShaderDebugName && g_origDll) {
        orig_GFSDK_Aftermath_GetShaderDebugName = (GFSDK_Aftermath_GetShaderDebugName_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_GetShaderDebugName");
    }
    if (!orig_GFSDK_Aftermath_GetShaderDebugName) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_GetShaderDebugName not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_GetShaderDebugName();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_GetShaderDebugName -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_GetShaderDebugNameSpirv
typedef void* (*GFSDK_Aftermath_GetShaderDebugNameSpirv_t)(...);
static GFSDK_Aftermath_GetShaderDebugNameSpirv_t orig_GFSDK_Aftermath_GetShaderDebugNameSpirv = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_GetShaderDebugNameSpirv(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_GetShaderDebugNameSpirv", 2);
    if (!orig_GFSDK_Aftermath_GetShaderDebugNameSpirv && g_origDll) {
        orig_GFSDK_Aftermath_GetShaderDebugNameSpirv = (GFSDK_Aftermath_GetShaderDebugNameSpirv_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_GetShaderDebugNameSpirv");
    }
    if (!orig_GFSDK_Aftermath_GetShaderDebugNameSpirv) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_GetShaderDebugNameSpirv not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_GetShaderDebugNameSpirv();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_GetShaderDebugNameSpirv -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_GetShaderHash
typedef void* (*GFSDK_Aftermath_GetShaderHash_t)(...);
static GFSDK_Aftermath_GetShaderHash_t orig_GFSDK_Aftermath_GetShaderHash = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_GetShaderHash(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_GetShaderHash", 2);
    if (!orig_GFSDK_Aftermath_GetShaderHash && g_origDll) {
        orig_GFSDK_Aftermath_GetShaderHash = (GFSDK_Aftermath_GetShaderHash_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_GetShaderHash");
    }
    if (!orig_GFSDK_Aftermath_GetShaderHash) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_GetShaderHash not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_GetShaderHash();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_GetShaderHash -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_GetShaderHashSpirv
typedef void* (*GFSDK_Aftermath_GetShaderHashSpirv_t)(...);
static GFSDK_Aftermath_GetShaderHashSpirv_t orig_GFSDK_Aftermath_GetShaderHashSpirv = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_GetShaderHashSpirv(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_GetShaderHashSpirv", 2);
    if (!orig_GFSDK_Aftermath_GetShaderHashSpirv && g_origDll) {
        orig_GFSDK_Aftermath_GetShaderHashSpirv = (GFSDK_Aftermath_GetShaderHashSpirv_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_GetShaderHashSpirv");
    }
    if (!orig_GFSDK_Aftermath_GetShaderHashSpirv) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_GetShaderHashSpirv not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_GetShaderHashSpirv();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_GetShaderHashSpirv -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_GpuCrashDump_CreateDecoder
typedef void* (*GFSDK_Aftermath_GpuCrashDump_CreateDecoder_t)(...);
static GFSDK_Aftermath_GpuCrashDump_CreateDecoder_t orig_GFSDK_Aftermath_GpuCrashDump_CreateDecoder = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_GpuCrashDump_CreateDecoder(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_GpuCrashDump_CreateDecoder", 2);
    if (!orig_GFSDK_Aftermath_GpuCrashDump_CreateDecoder && g_origDll) {
        orig_GFSDK_Aftermath_GpuCrashDump_CreateDecoder = (GFSDK_Aftermath_GpuCrashDump_CreateDecoder_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_GpuCrashDump_CreateDecoder");
    }
    if (!orig_GFSDK_Aftermath_GpuCrashDump_CreateDecoder) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_GpuCrashDump_CreateDecoder not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_GpuCrashDump_CreateDecoder();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_GpuCrashDump_CreateDecoder -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_GpuCrashDump_DestroyDecoder
typedef void* (*GFSDK_Aftermath_GpuCrashDump_DestroyDecoder_t)(...);
static GFSDK_Aftermath_GpuCrashDump_DestroyDecoder_t orig_GFSDK_Aftermath_GpuCrashDump_DestroyDecoder = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_GpuCrashDump_DestroyDecoder(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_GpuCrashDump_DestroyDecoder", 2);
    if (!orig_GFSDK_Aftermath_GpuCrashDump_DestroyDecoder && g_origDll) {
        orig_GFSDK_Aftermath_GpuCrashDump_DestroyDecoder = (GFSDK_Aftermath_GpuCrashDump_DestroyDecoder_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_GpuCrashDump_DestroyDecoder");
    }
    if (!orig_GFSDK_Aftermath_GpuCrashDump_DestroyDecoder) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_GpuCrashDump_DestroyDecoder not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_GpuCrashDump_DestroyDecoder();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_GpuCrashDump_DestroyDecoder -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_GpuCrashDump_GenerateJSON
typedef void* (*GFSDK_Aftermath_GpuCrashDump_GenerateJSON_t)(...);
static GFSDK_Aftermath_GpuCrashDump_GenerateJSON_t orig_GFSDK_Aftermath_GpuCrashDump_GenerateJSON = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_GpuCrashDump_GenerateJSON(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_GpuCrashDump_GenerateJSON", 2);
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GenerateJSON && g_origDll) {
        orig_GFSDK_Aftermath_GpuCrashDump_GenerateJSON = (GFSDK_Aftermath_GpuCrashDump_GenerateJSON_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_GpuCrashDump_GenerateJSON");
    }
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GenerateJSON) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_GpuCrashDump_GenerateJSON not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_GpuCrashDump_GenerateJSON();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_GpuCrashDump_GenerateJSON -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfo
typedef void* (*GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfo_t)(...);
static GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfo_t orig_GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfo = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfo(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfo", 2);
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfo && g_origDll) {
        orig_GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfo = (GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfo_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfo");
    }
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfo) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfo not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfo();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfo -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfoCount
typedef void* (*GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfoCount_t)(...);
static GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfoCount_t orig_GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfoCount = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfoCount(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfoCount", 2);
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfoCount && g_origDll) {
        orig_GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfoCount = (GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfoCount_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfoCount");
    }
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfoCount) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfoCount not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfoCount();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_GpuCrashDump_GetActiveShadersInfoCount -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_GpuCrashDump_GetBaseInfo
typedef void* (*GFSDK_Aftermath_GpuCrashDump_GetBaseInfo_t)(...);
static GFSDK_Aftermath_GpuCrashDump_GetBaseInfo_t orig_GFSDK_Aftermath_GpuCrashDump_GetBaseInfo = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_GpuCrashDump_GetBaseInfo(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_GpuCrashDump_GetBaseInfo", 2);
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GetBaseInfo && g_origDll) {
        orig_GFSDK_Aftermath_GpuCrashDump_GetBaseInfo = (GFSDK_Aftermath_GpuCrashDump_GetBaseInfo_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_GpuCrashDump_GetBaseInfo");
    }
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GetBaseInfo) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_GpuCrashDump_GetBaseInfo not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_GpuCrashDump_GetBaseInfo();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_GpuCrashDump_GetBaseInfo -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_GpuCrashDump_GetDescription
typedef void* (*GFSDK_Aftermath_GpuCrashDump_GetDescription_t)(...);
static GFSDK_Aftermath_GpuCrashDump_GetDescription_t orig_GFSDK_Aftermath_GpuCrashDump_GetDescription = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_GpuCrashDump_GetDescription(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_GpuCrashDump_GetDescription", 2);
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GetDescription && g_origDll) {
        orig_GFSDK_Aftermath_GpuCrashDump_GetDescription = (GFSDK_Aftermath_GpuCrashDump_GetDescription_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_GpuCrashDump_GetDescription");
    }
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GetDescription) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_GpuCrashDump_GetDescription not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_GpuCrashDump_GetDescription();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_GpuCrashDump_GetDescription -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_GpuCrashDump_GetDescriptionSize
typedef void* (*GFSDK_Aftermath_GpuCrashDump_GetDescriptionSize_t)(...);
static GFSDK_Aftermath_GpuCrashDump_GetDescriptionSize_t orig_GFSDK_Aftermath_GpuCrashDump_GetDescriptionSize = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_GpuCrashDump_GetDescriptionSize(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_GpuCrashDump_GetDescriptionSize", 2);
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GetDescriptionSize && g_origDll) {
        orig_GFSDK_Aftermath_GpuCrashDump_GetDescriptionSize = (GFSDK_Aftermath_GpuCrashDump_GetDescriptionSize_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_GpuCrashDump_GetDescriptionSize");
    }
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GetDescriptionSize) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_GpuCrashDump_GetDescriptionSize not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_GpuCrashDump_GetDescriptionSize();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_GpuCrashDump_GetDescriptionSize -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_GpuCrashDump_GetDeviceInfo
typedef void* (*GFSDK_Aftermath_GpuCrashDump_GetDeviceInfo_t)(...);
static GFSDK_Aftermath_GpuCrashDump_GetDeviceInfo_t orig_GFSDK_Aftermath_GpuCrashDump_GetDeviceInfo = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_GpuCrashDump_GetDeviceInfo(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_GpuCrashDump_GetDeviceInfo", 2);
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GetDeviceInfo && g_origDll) {
        orig_GFSDK_Aftermath_GpuCrashDump_GetDeviceInfo = (GFSDK_Aftermath_GpuCrashDump_GetDeviceInfo_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_GpuCrashDump_GetDeviceInfo");
    }
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GetDeviceInfo) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_GpuCrashDump_GetDeviceInfo not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_GpuCrashDump_GetDeviceInfo();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_GpuCrashDump_GetDeviceInfo -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfo
typedef void* (*GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfo_t)(...);
static GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfo_t orig_GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfo = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfo(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfo", 2);
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfo && g_origDll) {
        orig_GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfo = (GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfo_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfo");
    }
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfo) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfo not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfo();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfo -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfoCount
typedef void* (*GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfoCount_t)(...);
static GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfoCount_t orig_GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfoCount = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfoCount(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfoCount", 2);
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfoCount && g_origDll) {
        orig_GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfoCount = (GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfoCount_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfoCount");
    }
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfoCount) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfoCount not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfoCount();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_GpuCrashDump_GetEventMarkersInfoCount -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_GpuCrashDump_GetGpuInfo
typedef void* (*GFSDK_Aftermath_GpuCrashDump_GetGpuInfo_t)(...);
static GFSDK_Aftermath_GpuCrashDump_GetGpuInfo_t orig_GFSDK_Aftermath_GpuCrashDump_GetGpuInfo = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_GpuCrashDump_GetGpuInfo(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_GpuCrashDump_GetGpuInfo", 2);
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GetGpuInfo && g_origDll) {
        orig_GFSDK_Aftermath_GpuCrashDump_GetGpuInfo = (GFSDK_Aftermath_GpuCrashDump_GetGpuInfo_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_GpuCrashDump_GetGpuInfo");
    }
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GetGpuInfo) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_GpuCrashDump_GetGpuInfo not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_GpuCrashDump_GetGpuInfo();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_GpuCrashDump_GetGpuInfo -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_GpuCrashDump_GetGpuInfoCount
typedef void* (*GFSDK_Aftermath_GpuCrashDump_GetGpuInfoCount_t)(...);
static GFSDK_Aftermath_GpuCrashDump_GetGpuInfoCount_t orig_GFSDK_Aftermath_GpuCrashDump_GetGpuInfoCount = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_GpuCrashDump_GetGpuInfoCount(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_GpuCrashDump_GetGpuInfoCount", 2);
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GetGpuInfoCount && g_origDll) {
        orig_GFSDK_Aftermath_GpuCrashDump_GetGpuInfoCount = (GFSDK_Aftermath_GpuCrashDump_GetGpuInfoCount_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_GpuCrashDump_GetGpuInfoCount");
    }
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GetGpuInfoCount) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_GpuCrashDump_GetGpuInfoCount not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_GpuCrashDump_GetGpuInfoCount();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_GpuCrashDump_GetGpuInfoCount -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_GpuCrashDump_GetJSON
typedef void* (*GFSDK_Aftermath_GpuCrashDump_GetJSON_t)(...);
static GFSDK_Aftermath_GpuCrashDump_GetJSON_t orig_GFSDK_Aftermath_GpuCrashDump_GetJSON = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_GpuCrashDump_GetJSON(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_GpuCrashDump_GetJSON", 2);
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GetJSON && g_origDll) {
        orig_GFSDK_Aftermath_GpuCrashDump_GetJSON = (GFSDK_Aftermath_GpuCrashDump_GetJSON_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_GpuCrashDump_GetJSON");
    }
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GetJSON) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_GpuCrashDump_GetJSON not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_GpuCrashDump_GetJSON();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_GpuCrashDump_GetJSON -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_GpuCrashDump_GetPageFaultInfo
typedef void* (*GFSDK_Aftermath_GpuCrashDump_GetPageFaultInfo_t)(...);
static GFSDK_Aftermath_GpuCrashDump_GetPageFaultInfo_t orig_GFSDK_Aftermath_GpuCrashDump_GetPageFaultInfo = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_GpuCrashDump_GetPageFaultInfo(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_GpuCrashDump_GetPageFaultInfo", 2);
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GetPageFaultInfo && g_origDll) {
        orig_GFSDK_Aftermath_GpuCrashDump_GetPageFaultInfo = (GFSDK_Aftermath_GpuCrashDump_GetPageFaultInfo_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_GpuCrashDump_GetPageFaultInfo");
    }
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GetPageFaultInfo) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_GpuCrashDump_GetPageFaultInfo not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_GpuCrashDump_GetPageFaultInfo();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_GpuCrashDump_GetPageFaultInfo -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_GpuCrashDump_GetSystemInfo
typedef void* (*GFSDK_Aftermath_GpuCrashDump_GetSystemInfo_t)(...);
static GFSDK_Aftermath_GpuCrashDump_GetSystemInfo_t orig_GFSDK_Aftermath_GpuCrashDump_GetSystemInfo = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_GpuCrashDump_GetSystemInfo(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_GpuCrashDump_GetSystemInfo", 2);
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GetSystemInfo && g_origDll) {
        orig_GFSDK_Aftermath_GpuCrashDump_GetSystemInfo = (GFSDK_Aftermath_GpuCrashDump_GetSystemInfo_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_GpuCrashDump_GetSystemInfo");
    }
    if (!orig_GFSDK_Aftermath_GpuCrashDump_GetSystemInfo) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_GpuCrashDump_GetSystemInfo not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_GpuCrashDump_GetSystemInfo();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_GpuCrashDump_GetSystemInfo -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_ReleaseContextHandle
typedef void* (*GFSDK_Aftermath_ReleaseContextHandle_t)(...);
static GFSDK_Aftermath_ReleaseContextHandle_t orig_GFSDK_Aftermath_ReleaseContextHandle = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_ReleaseContextHandle(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_ReleaseContextHandle", 2);
    if (!orig_GFSDK_Aftermath_ReleaseContextHandle && g_origDll) {
        orig_GFSDK_Aftermath_ReleaseContextHandle = (GFSDK_Aftermath_ReleaseContextHandle_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_ReleaseContextHandle");
    }
    if (!orig_GFSDK_Aftermath_ReleaseContextHandle) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_ReleaseContextHandle not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_ReleaseContextHandle();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_ReleaseContextHandle -> %p", result);
    return result;
}

// Original function pointer for GFSDK_Aftermath_SetEventMarker
typedef void* (*GFSDK_Aftermath_SetEventMarker_t)(...);
static GFSDK_Aftermath_SetEventMarker_t orig_GFSDK_Aftermath_SetEventMarker = nullptr;

extern "C" __declspec(dllexport) void* GFSDK_Aftermath_SetEventMarker(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GFSDK_Aftermath_SetEventMarker", 2);
    if (!orig_GFSDK_Aftermath_SetEventMarker && g_origDll) {
        orig_GFSDK_Aftermath_SetEventMarker = (GFSDK_Aftermath_SetEventMarker_t)GetProcAddress(g_origDll, "GFSDK_Aftermath_SetEventMarker");
    }
    if (!orig_GFSDK_Aftermath_SetEventMarker) {
        if (g_logger) g_logger->Log("[ERROR] GFSDK_Aftermath_SetEventMarker not found!");
        return nullptr;
    }
    void* result = orig_GFSDK_Aftermath_SetEventMarker();
    if (g_logger) g_logger->LogFormat("[RETURN] GFSDK_Aftermath_SetEventMarker -> %p", result);
    return result;
}

// Original function pointer for GetShaderDebugName
typedef void* (*GetShaderDebugName_t)(...);
static GetShaderDebugName_t orig_GetShaderDebugName = nullptr;

extern "C" __declspec(dllexport) void* GetShaderDebugName(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GetShaderDebugName", 2);
    if (!orig_GetShaderDebugName && g_origDll) {
        orig_GetShaderDebugName = (GetShaderDebugName_t)GetProcAddress(g_origDll, "GetShaderDebugName");
    }
    if (!orig_GetShaderDebugName) {
        if (g_logger) g_logger->Log("[ERROR] GetShaderDebugName not found!");
        return nullptr;
    }
    void* result = orig_GetShaderDebugName();
    if (g_logger) g_logger->LogFormat("[RETURN] GetShaderDebugName -> %p", result);
    return result;
}

// Original function pointer for GetShaderDebugNameSpirv
typedef void* (*GetShaderDebugNameSpirv_t)(...);
static GetShaderDebugNameSpirv_t orig_GetShaderDebugNameSpirv = nullptr;

extern "C" __declspec(dllexport) void* GetShaderDebugNameSpirv(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GetShaderDebugNameSpirv", 2);
    if (!orig_GetShaderDebugNameSpirv && g_origDll) {
        orig_GetShaderDebugNameSpirv = (GetShaderDebugNameSpirv_t)GetProcAddress(g_origDll, "GetShaderDebugNameSpirv");
    }
    if (!orig_GetShaderDebugNameSpirv) {
        if (g_logger) g_logger->Log("[ERROR] GetShaderDebugNameSpirv not found!");
        return nullptr;
    }
    void* result = orig_GetShaderDebugNameSpirv();
    if (g_logger) g_logger->LogFormat("[RETURN] GetShaderDebugNameSpirv -> %p", result);
    return result;
}

// Original function pointer for GetShaderHashSpirv
typedef void* (*GetShaderHashSpirv_t)(...);
static GetShaderHashSpirv_t orig_GetShaderHashSpirv = nullptr;

extern "C" __declspec(dllexport) void* GetShaderHashSpirv(...) {
    // Log with full call stack (shows caller function names and addresses)
    if (g_logger) g_logger->LogWithCallStack("[CALL] GetShaderHashSpirv", 2);
    if (!orig_GetShaderHashSpirv && g_origDll) {
        orig_GetShaderHashSpirv = (GetShaderHashSpirv_t)GetProcAddress(g_origDll, "GetShaderHashSpirv");
    }
    if (!orig_GetShaderHashSpirv) {
        if (g_logger) g_logger->Log("[ERROR] GetShaderHashSpirv not found!");
        return nullptr;
    }
    void* result = orig_GetShaderHashSpirv();
    if (g_logger) g_logger->LogFormat("[RETURN] GetShaderHashSpirv -> %p", result);
    return result;
}

