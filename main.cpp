#include <windows.h>
#include <wincrypt.h>
#include <iostream>

// Typedef for the original CertVerifyCertificateChainPolicy API
typedef BOOL(WINAPI* CertVerifyCertificateChainPolicy_t)(
    LPCSTR pszPolicyOID,
    PCCERT_CHAIN_CONTEXT pChainContext,
    PCERT_CHAIN_POLICY_PARA pPolicyPara,
    PCERT_CHAIN_POLICY_STATUS pPolicyStatus);

// Pointer to store original function address
static CertVerifyCertificateChainPolicy_t original_CertVerifyCertificateChainPolicy = nullptr;

// Hooked function that forcibly revokes trust by returning CERT_E_REVOKED
BOOL WINAPI hooked_CertVerifyCertificateChainPolicy(
    LPCSTR pszPolicyOID,
    PCCERT_CHAIN_CONTEXT pChainContext,
    PCERT_CHAIN_POLICY_PARA pPolicyPara,
    PCERT_CHAIN_POLICY_STATUS pPolicyStatus)
{
    // Call original function for logging or fallback (optional)
    BOOL result = original_CertVerifyCertificateChainPolicy(pszPolicyOID, pChainContext, pPolicyPara, pPolicyStatus);

    // Force revocation error unconditionally
    if (pPolicyStatus) {
        pPolicyStatus->dwError = CERT_E_REVOKED; // Certificate revoked error
    }

    SetLastError(ERROR_ACCESS_DENIED); // Optional: set last error

    return FALSE; // Fail trust validation
}

// Helper function to write a relative jump from src to dest (5 bytes)
void WriteJump(void* src, void* dest)
{
    DWORD oldProtect;
    BYTE* pSrc = reinterpret_cast<BYTE*>(src);

    // Change memory protection to allow writing
    if (!VirtualProtect(pSrc, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        MessageBoxA(NULL, "VirtualProtect failed", "Error", MB_OK);
        return;
    }

    pSrc[0] = 0xE9; // JMP opcode
    intptr_t offset = (BYTE*)dest - pSrc - 5; // Relative offset for JMP
    memcpy(pSrc + 1, &offset, 4);

    // Restore original protection
    VirtualProtect(pSrc, 5, oldProtect, &oldProtect);
}

// DLL entry point: apply hook on process attach
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        HMODULE hCrypt32 = GetModuleHandleA("crypt32.dll");
        if (!hCrypt32) {
            MessageBoxA(NULL, "Failed to get handle to crypt32.dll", "Error", MB_OK);
            return FALSE;
        }

        // Resolve original API address
        original_CertVerifyCertificateChainPolicy = (CertVerifyCertificateChainPolicy_t)GetProcAddress(
            hCrypt32, "CertVerifyCertificateChainPolicy");

        if (!original_CertVerifyCertificateChainPolicy) {
            MessageBoxA(NULL, "Failed to get CertVerifyCertificateChainPolicy address", "Error", MB_OK);
            return FALSE;
        }

        // Write jump instruction to hook the function
        WriteJump((void*)original_CertVerifyCertificateChainPolicy, (void*)hooked_CertVerifyCertificateChainPolicy);
    }
    return TRUE;
}
