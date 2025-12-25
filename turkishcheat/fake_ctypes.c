#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif

// --- Globals for DLL path ---
// We capture the DLL's own path in DllMain to find the real _ctypes.pyd reliably.
static char g_dll_dir[MAX_PATH] = {0};

// --- DllMain ---
// This function is called when the DLL is loaded, allowing us to get its path.
#ifdef _WIN32
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        char dll_path[MAX_PATH] = {0};
        DWORD path_len = GetModuleFileNameA(hinstDLL, dll_path, MAX_PATH);

        if (path_len == 0 || path_len >= MAX_PATH) {
            // If we can't get the path, we can't proceed.
            return FALSE;
        }

        // Get just the directory part by finding the last backslash.
        // Use portable strncpy instead of strncpy_s
        strncpy(g_dll_dir, dll_path, MAX_PATH - 1);
        g_dll_dir[MAX_PATH - 1] = '\0';  // Ensure null termination

        char* last_slash = strrchr(g_dll_dir, '\\');
        if (last_slash) {
            *last_slash = '\0'; // Terminate the string at the last slash.
        }
    }
    return TRUE;
}
#endif

// Global flag to prevent infinite recursion
static int shim_already_loaded = 0;

PyMODINIT_FUNC PyInit__ctypes(void) {
    if (shim_already_loaded) {
        fprintf(stderr, "\n[C SHIM] *** RECURSIVE CALL BLOCKED ***\n");
        PyErr_SetString(PyExc_RuntimeError, "Recursive shim call");
        return NULL;
    }
    shim_already_loaded = 1;
    
    printf("\n");
    printf("================================================================================\n");
    printf("                     FAKE CTYPES SHIM ACTIVATED\n");
    printf("================================================================================\n");
    
    if (!Py_IsInitialized()) {
        fprintf(stderr, "[FATAL] Python not initialized\n");
        PyErr_SetString(PyExc_RuntimeError, "Python not initialized");
        return NULL;
    }
    
    // ============================================================================
    // STEP 1: Get paths
    // ============================================================================
    printf("\n[STEP 1] Getting shim's own directory...\n");
    
    if (g_dll_dir[0] == '\0') {
        fprintf(stderr, "[FATAL] Could not determine DLL directory via DllMain.\n");
        PyErr_SetString(PyExc_RuntimeError, "Could not get DLL directory");
        return NULL;
    }
    printf("[INFO] Shim directory: %s\n", g_dll_dir);
    
    // Build path to real DLL
    char real_ctypes_path[1024];
    snprintf(real_ctypes_path, sizeof(real_ctypes_path), 
             "%s\\ctypes_orig\\_ctypes.pyd", g_dll_dir);
    
    printf("[INFO] Real _ctypes location: %s\n", real_ctypes_path);
    
    // ============================================================================
    // STEP 2: Load the DLL directly using Windows API
    // ============================================================================
    printf("\n[STEP 2] Loading real _ctypes.pyd using LoadLibrary...\n");
    
#ifdef _WIN32
    HMODULE real_dll = LoadLibraryA(real_ctypes_path);
    if (!real_dll) {
        fprintf(stderr, "[FATAL] LoadLibrary failed for: %s\n", real_ctypes_path);
        fprintf(stderr, "[ERROR] GetLastError: %lu\n", GetLastError());
        PyErr_SetString(PyExc_RuntimeError, "Cannot load real _ctypes.pyd");
        return NULL;
    }
    
    printf("[SUCCESS] DLL loaded at address: %p\n", (void*)real_dll);
    
    // ============================================================================
    // STEP 3: Get the PyInit function from the real DLL
    // ============================================================================
    printf("\n[STEP 3] Looking for PyInit__ctypes in real DLL...\n");
    
    // Python 3 uses PyInit__ctypes
    typedef PyObject* (*PyInitFunc)(void);
    PyInitFunc real_init = (PyInitFunc)GetProcAddress(real_dll, "PyInit__ctypes");
    
    if (!real_init) {
        fprintf(stderr, "[FATAL] Cannot find PyInit__ctypes in real DLL\n");
        FreeLibrary(real_dll);
        PyErr_SetString(PyExc_RuntimeError, "Real _ctypes.pyd missing PyInit function");
        return NULL;
    }
    
    printf("[SUCCESS] Found PyInit__ctypes at address: %p\n", (void*)real_init);
    
    // ============================================================================
    // STEP 4: Call the real PyInit function
    // ============================================================================
    printf("\n[STEP 4] Calling real PyInit__ctypes()...\n");
    
    PyObject* real_module = real_init();
    
    if (!real_module) {
        fprintf(stderr, "[FATAL] Real PyInit__ctypes() returned NULL\n");
        FreeLibrary(real_dll);
        if (PyErr_Occurred()) {
            PyErr_Print();
        }
        return NULL;
    }
    
    printf("[SUCCESS] Real module initialized: %p\n", (void*)real_module);
    
    // Verify it's a module
    if (!PyModule_Check(real_module)) {
        fprintf(stderr, "[WARNING] Returned object is not a module!\n");
    }
    
    // ============================================================================
    // STEP 5: Add to sys.modules
    // ============================================================================
    printf("\n[STEP 5] Adding real _ctypes to sys.modules...\n");
    
    PyObject* sys_modules = PyImport_GetModuleDict();
    if (sys_modules) {
        if (PyDict_SetItemString(sys_modules, "_ctypes", real_module) < 0) {
            fprintf(stderr, "[ERROR] Cannot add to sys.modules\n");
            Py_DECREF(real_module);
            FreeLibrary(real_dll);
            return NULL;
        }
        printf("[SUCCESS] Added to sys.modules['_ctypes']\n");
    }
    
#else
    fprintf(stderr, "[FATAL] This shim only works on Windows\n");
    PyErr_SetString(PyExc_RuntimeError, "Windows-only shim");
    return NULL;
#endif
    
    // ============================================================================
    // STEP 6: Install recovery payload
    // ============================================================================
    printf("\n[STEP 6] Installing recovery payload...\n");
    
    // Since the CWD is the original exe's dir, we need to find recovery_payload.py
    // in the shim's directory.
    char recovery_payload_path[1024];
    snprintf(recovery_payload_path, sizeof(recovery_payload_path), 
             "%s\\recovery_payload.py", g_dll_dir);

    FILE* payload_fp = fopen(recovery_payload_path, "r");
    if (payload_fp) {
        int result = PyRun_SimpleFile(payload_fp, recovery_payload_path);
        if (result == 0) {
            printf("[SUCCESS] Recovery payload installed\n");
        } else {
            fprintf(stderr, "[WARNING] Recovery payload had errors\n");
            PyErr_Clear();
        }
        fclose(payload_fp);
    } else {
        fprintf(stderr, "[INFO] recovery_payload.py not found at %s (skipping)\n", recovery_payload_path);
    }
    
    // ============================================================================
    // DONE
    // ============================================================================
    printf("\n");
    printf("================================================================================\n");
    printf("                   SHIM COMPLETE - APPLICATION STARTING\n");
    printf("================================================================================\n\n");
    
    // Return the real module (already has correct refcount from real_init)
    return real_module;
}