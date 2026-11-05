using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace PacketHound.Core;

/// <summary>
/// Verifies a file's Authenticode signature — embedded, or via a Windows security catalog
/// (most Windows binaries are catalog-signed) — and returns the signer's common name.
/// Revocation and network retrieval are disabled: PacketHound itself has no outbound access.
/// </summary>
public static class Signature
{
    /// <summary>The verified signer's CN (e.g. "Microsoft Windows"), or null when unsigned/invalid.</summary>
    public static string? GetVerifiedSigner(string path)
    {
        try
        {
            return VerifyEmbedded(path) ?? VerifyCatalog(path, "SHA256") ?? VerifyCatalog(path, "SHA1");
        }
        catch (Exception ex)
        {
            Log.Error($"Signature check failed for {path}", ex);
            return null;
        }
    }

    static string? VerifyEmbedded(string path)
    {
        var file = new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(), pcwszFilePath = path };
        var info = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(file, info, false);
            return Verify(WTD_CHOICE_FILE, info);
        }
        finally
        {
            Marshal.DestroyStructure<WINTRUST_FILE_INFO>(info);
            Marshal.FreeHGlobal(info);
        }
    }

    static string? VerifyCatalog(string path, string hashAlgorithm)
    {
        if (!CryptCATAdminAcquireContext2(out var catAdmin, IntPtr.Zero, hashAlgorithm, IntPtr.Zero, 0)) return null;
        var catInfo = IntPtr.Zero;
        try
        {
            byte[] hash;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                uint size = 0;
                CryptCATAdminCalcHashFromFileHandle2(catAdmin, fs.SafeFileHandle, ref size, null, 0);
                if (size == 0) return null;
                hash = new byte[size];
                if (!CryptCATAdminCalcHashFromFileHandle2(catAdmin, fs.SafeFileHandle, ref size, hash, 0)) return null;
            }

            catInfo = CryptCATAdminEnumCatalogFromHash(catAdmin, hash, (uint)hash.Length, 0, IntPtr.Zero);
            if (catInfo == IntPtr.Zero) return null;

            var ci = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
            if (!CryptCATCatalogInfoFromContext(catInfo, ref ci, 0)) return null;

            var hashPtr = Marshal.AllocHGlobal(hash.Length);
            var cat = new WINTRUST_CATALOG_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                pcwszCatalogFilePath = ci.wszCatalogFile,
                pcwszMemberTag = Convert.ToHexString(hash),
                pcwszMemberFilePath = path,
                pbCalculatedFileHash = hashPtr,
                cbCalculatedFileHash = (uint)hash.Length,
                hCatAdmin = catAdmin,
            };
            var info = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
            try
            {
                Marshal.Copy(hash, 0, hashPtr, hash.Length);
                Marshal.StructureToPtr(cat, info, false);
                return Verify(WTD_CHOICE_CATALOG, info);
            }
            finally
            {
                Marshal.DestroyStructure<WINTRUST_CATALOG_INFO>(info);
                Marshal.FreeHGlobal(info);
                Marshal.FreeHGlobal(hashPtr);
            }
        }
        finally
        {
            if (catInfo != IntPtr.Zero) CryptCATAdminReleaseCatalogContext(catAdmin, catInfo, 0);
            CryptCATAdminReleaseContext(catAdmin, 0);
        }
    }

    static string? Verify(uint unionChoice, IntPtr info)
    {
        var data = new WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
            dwUIChoice = WTD_UI_NONE,
            fdwRevocationChecks = WTD_REVOKE_NONE,
            dwUnionChoice = unionChoice,
            pInfo = info,
            dwStateAction = WTD_STATEACTION_VERIFY,
            dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
        };
        var action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        try
        {
            if (WinVerifyTrust(new IntPtr(-1), ref action, ref data) != 0) return null;

            var provData = WTHelperProvDataFromStateData(data.hWVTStateData);
            if (provData == IntPtr.Zero) return null;
            var signer = WTHelperGetProvSignerFromChain(provData, 0, false, 0);
            if (signer == IntPtr.Zero) return null;

            // CRYPT_PROVIDER_SGNR: DWORD cbStruct; FILETIME sftVerifyAsOf; DWORD csCertChain; CRYPT_PROVIDER_CERT* pasCertChain
            // csCertChain is at offset 12 and pasCertChain at 16 on both x86 and x64.
            if (Marshal.ReadInt32(signer, 12) == 0) return null;
            var chain = Marshal.ReadIntPtr(signer, 16);
            if (chain == IntPtr.Zero) return null;
            // CRYPT_PROVIDER_CERT: DWORD cbStruct; PCCERT_CONTEXT pCert
            var certContext = Marshal.ReadIntPtr(chain, IntPtr.Size);
            if (certContext == IntPtr.Zero) return null;

            using var cert = new X509Certificate2(certContext);
            return cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
        }
        finally
        {
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(new IntPtr(-1), ref action, ref data);
        }
    }

    static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    const uint WTD_UI_NONE = 2;
    const uint WTD_REVOKE_NONE = 0;
    const uint WTD_CHOICE_FILE = 1;
    const uint WTD_CHOICE_CATALOG = 2;
    const uint WTD_STATEACTION_VERIFY = 1;
    const uint WTD_STATEACTION_CLOSE = 2;
    const uint WTD_REVOCATION_CHECK_NONE = 0x10;
    const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszCatalogFilePath;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberTag;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pInfo;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    [DllImport("wintrust.dll")]
    static extern IntPtr WTHelperProvDataFromStateData(IntPtr hStateData);

    [DllImport("wintrust.dll")]
    static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr pProvData, uint idxSigner, bool fCounterSigner, uint idxCounterSigner);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, IntPtr pgSubsystem, string pwszHashAlgorithm,
        IntPtr pStrongHashPolicy, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, SafeFileHandle hFile, ref uint pcbHash,
        byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags,
        IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

    [DllImport("wintrust.dll")]
    static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll")]
    static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);
}
