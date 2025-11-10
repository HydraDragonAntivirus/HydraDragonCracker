#include "pch.h"

// ===================================================================================
//              ANA MANTIK DOSYASI
// ===================================================================================
// Talimatýn üzerine, bu dosya önce "pch.h" dosyasýný (içinde sadece windows.h var)
// ve sonra diðer tüm C++ header'larýný içermektedir.
// ===================================================================================

// --- Gerekli Standart C++ Kütüphaneleri ---
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <atomic>
#include <shlobj.h>      // SHGetKnownFolderPath için (windows.h'da deðilse diye garanti)
#include <strsafe.h>     // StringCchPrintfA için (windows.h'da deðilse diye garanti)


// --- D3DCompile Tipi Tanýmlamalarý ---
struct ID3DBlob;
struct D3D_SHADER_MACRO;
typedef long HRESULT;

typedef HRESULT(WINAPI* t_D3DCompile)(
    LPCVOID pSrcData, SIZE_T SrcDataSize, LPCSTR pSourceName,
    const D3D_SHADER_MACRO* pDefines, void* pInclude,
    LPCSTR pEntrypoint, LPCSTR pTarget, UINT Flags1, UINT Flags2,
    ID3DBlob** ppCode, ID3DBlob** ppErrorMsgs
    );

// ===================================================================================
// BÖLÜM 1: KAYNAK KODU ANALÝZ MOTORU (EXTRACTOR MANTIÐI)
// ===================================================================================
namespace CodeExtractor
{
    // ... Öncekiyle ayný, tam extractor kodu ...
    struct Found { std::string kind; size_t start; size_t end; std::string name; };
    struct Filtered { std::string orig; std::string masked; };
    static std::string sanitize(const std::string& s) { std::string out; for (char c : s) { if (isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '-') out.push_back(c); else out.push_back('_'); } if (out.size() > 150) out.resize(150); return out; }
    static size_t skip_spaces(const std::string& s, size_t pos) { while (pos < s.size() && isspace(static_cast<unsigned char>(s[pos]))) ++pos; return pos; }
    static std::pair<size_t, size_t> extract_braced_block(const std::string& masked, size_t brace_idx) { if (brace_idx >= masked.size() || masked[brace_idx] != '{') return { std::string::npos, std::string::npos }; size_t i = brace_idx; int depth = 0; for (; i < masked.size(); ++i) { if (masked[i] == '{') ++depth; else if (masked[i] == '}') { --depth; if (depth == 0) return { brace_idx, i + 1 }; } } return { std::string::npos, std::string::npos }; }
    static Filtered mask_comments_and_strings(const std::string& s) { Filtered res; res.orig = s; res.masked = s; enum State { NORMAL, SLASH, LINE_COMMENT, BLOCK_COMMENT, SQUOTE, DQUOTE, RSTRING }; State st = NORMAL; char prev = 0; for (size_t i = 0; i < s.size(); ++i) { char c = s[i]; switch (st) { case NORMAL: if (c == '/') st = SLASH; else if (c == '\'') { st = SQUOTE; res.masked[i] = ' '; } else if (c == '"') { st = DQUOTE; res.masked[i] = ' '; } else if (c == 'R' && i + 1 < s.size() && s[i + 1] == '"') { st = RSTRING; res.masked[i] = ' '; } break; case SLASH: if (c == '/') { st = LINE_COMMENT; if (i > 0) res.masked[i - 1] = ' '; res.masked[i] = ' '; } else if (c == '*') { st = BLOCK_COMMENT; if (i > 0) res.masked[i - 1] = ' '; res.masked[i] = ' '; } else { st = NORMAL; } break; case LINE_COMMENT: res.masked[i] = ' '; if (c == '\n') st = NORMAL; break; case BLOCK_COMMENT: res.masked[i] = ' '; if (prev == '*' && c == '/') { st = NORMAL; res.masked[i] = ' '; } break; case SQUOTE: res.masked[i] = ' '; if (c == '\\') { if (i + 1 < s.size()) { res.masked[i + 1] = ' '; ++i; } } else if (c == '\'') st = NORMAL; break; case DQUOTE: res.masked[i] = ' '; if (c == '\\') { if (i + 1 < s.size()) { res.masked[i + 1] = ' '; ++i; } } else if (c == '"') st = NORMAL; break; case RSTRING: res.masked[i] = ' '; if (c == ')' && i + 1 < s.size() && s[i + 1] == '"') { res.masked[i + 1] = ' '; ++i; st = NORMAL; } break; } prev = c; } return res; }
                                                                                                                                                                                                                                                                                                                        static std::vector<Found> scan_for_definitions(const Filtered& f) { std::vector<Found> res; const std::string& m = f.masked; const std::string& o = f.orig; size_t n = m.size(); std::vector<std::string> keywords = { "class", "struct", "union", "enum", "namespace", "cbuffer", "technique", "sampler", "texture" }; for (size_t pos = 0; pos < n; ) { size_t next_pos = std::string::npos; std::string found_kw; for (auto& kw : keywords) { size_t p = m.find(kw, pos); if (p != std::string::npos) { bool left_ok = (p == 0) || !isalnum(static_cast<unsigned char>(m[p - 1])); bool right_ok = (p + kw.size() >= n) || !isalnum(static_cast<unsigned char>(m[p + kw.size()])); if (left_ok && right_ok) { if (next_pos == std::string::npos || p < next_pos) { next_pos = p; found_kw = kw; } } } } if (next_pos == std::string::npos) break; size_t idstart = skip_spaces(m, next_pos + found_kw.size()); size_t idend = idstart; while (idend < n && (isalnum(static_cast<unsigned char>(m[idend])) || m[idend] == '_' || m[idend] == ':')) ++idend; std::string name = (idend > idstart) ? o.substr(idstart, idend - idstart) : std::string(); size_t brace_pos = m.find('{', idend); if (brace_pos == std::string::npos) { pos = idend; continue; } auto block = extract_braced_block(m, brace_pos); if (block.first != std::string::npos) { res.push_back({ found_kw, next_pos, block.second, sanitize(name.empty() ? ("anon_" + found_kw) : name) }); pos = block.second; } else { pos = brace_pos + 1; } } std::sort(res.begin(), res.end(), [](const Found& a, const Found& b) { return a.start < b.start; }); return res; }
}

// ===================================================================================
// BÖLÜM 2: DLL PROXY VE ANA MANTIK
// ===================================================================================
static HMODULE g_hOriginalDll = NULL;
static t_D3DCompile g_pOrigD3DCompile = NULL;
static std::filesystem::path g_dumpPath;
static std::atomic<int> g_totalDumps = 0;

void AnalyzeAndSaveSnippets(LPCVOID pSrcData, SIZE_T SrcDataSize) { if (!pSrcData || SrcDataSize == 0) return; std::string source_code(static_cast<const char*>(pSrcData), SrcDataSize); auto filtered = CodeExtractor::mask_comments_and_strings(source_code); auto snippets = CodeExtractor::scan_for_definitions(filtered); if (snippets.empty()) { int dumpIndex = g_totalDumps.fetch_add(1); std::wstringstream fallbackName; fallbackName << L"raw_dump_" << dumpIndex << L".hlsl"; std::ofstream outFile(g_dumpPath / fallbackName.str(), std::ios::binary); if (outFile) outFile.write(source_code.c_str(), source_code.length()); } else { for (const auto& snippet : snippets) { if (snippet.start >= source_code.length() || snippet.end > source_code.length() || snippet.start >= snippet.end) continue; int dumpIndex = g_totalDumps.fetch_add(1); std::string snippet_code = source_code.substr(snippet.start, snippet.end - snippet.start); std::wstring sanitized_name; for (char c : snippet.name) { if (iswprint(c)) sanitized_name += c; } std::wstringstream fileName; fileName << L"snippet_" << dumpIndex << L"_" << std::wstring(snippet.kind.begin(), snippet.kind.end()) << L"_" << sanitized_name << L".hlsl"; std::ofstream outFile(g_dumpPath / fileName.str(), std::ios::binary); if (outFile) outFile.write(snippet_code.c_str(), snippet_code.length()); } } }
void LoadOriginalDll() { g_hOriginalDll = LoadLibraryW(L"orig.dll"); if (!g_hOriginalDll) { MessageBoxA(NULL, "'orig.dll' bulunamadi! Lutfen orijinal 'd3dcompiler_43.dll' dosyasinin adini 'orig.dll' olarak degistirip programin yanina kopyalayin.", "Proxy DLL Hatasi", MB_OK | MB_ICONERROR); return; } g_pOrigD3DCompile = (t_D3DCompile)GetProcAddress(g_hOriginalDll, "D3DCompile"); }

extern "C" __declspec(dllexport) HRESULT WINAPI D3DCompile(LPCVOID pSrcData, SIZE_T SrcDataSize, LPCSTR pSourceName, const D3D_SHADER_MACRO* pDefines, void* pInclude, LPCSTR pEntrypoint, LPCSTR pTarget, UINT Flags1, UINT Flags2, ID3DBlob** ppCode, ID3DBlob** ppErrorMsgs) { AnalyzeAndSaveSnippets(pSrcData, SrcDataSize); if (g_pOrigD3DCompile) { return g_pOrigD3DCompile(pSrcData, SrcDataSize, pSourceName, pDefines, pInclude, pEntrypoint, pTarget, Flags1, Flags2, ppCode, ppErrorMsgs); } return E_FAIL; }

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) { switch (ul_reason_for_call) { case DLL_PROCESS_ATTACH: { DisableThreadLibraryCalls(hModule); PWSTR path = NULL; if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &path))) { g_dumpPath = path; g_dumpPath /= "D3D_Source_Snippets"; CoTaskMemFree(path); } else { g_dumpPath = std::filesystem::current_path() / "D3D_Source_Snippets"; } std::filesystem::create_directories(g_dumpPath); LoadOriginalDll(); break; } case DLL_PROCESS_DETACH: { if (g_hOriginalDll) { FreeLibrary(g_hOriginalDll); g_hOriginalDll = NULL; } break; } } return TRUE; }
