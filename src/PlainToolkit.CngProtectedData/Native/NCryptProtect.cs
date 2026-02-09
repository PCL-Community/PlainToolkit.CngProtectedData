using System.Runtime.InteropServices;
using System.Text;

// ReSharper disable InconsistentNaming

namespace PlainToolkit.CngProtectedData.Native;

public static partial class NCryptProtect
{
    [StructLayout(LayoutKind.Sequential)]
    public struct NCRYPT_ALLOC_PARA
    {
        public int cbSize;
        public unsafe delegate* unmanaged[Stdcall]<UIntPtr, IntPtr> pfnAlloc;
        public unsafe delegate* unmanaged[Stdcall]<IntPtr, void> pfnFree;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct NCRYPT_PROTECT_STREAM_INFO
    {
        public unsafe delegate* unmanaged[Stdcall]<IntPtr, byte*, UIntPtr, int, int> pfnStreamOutput;
        public IntPtr pvCallbackCtxt;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct NCRYPT_PROTECT_STREAM_INFO_EX
    {
        public unsafe delegate* unmanaged[Stdcall]<IntPtr, byte*, UIntPtr, IntPtr, int, int> pfnStreamOutput;
        public IntPtr pvCallbackCtxt;
    }

    [LibraryImport("ncrypt.dll")]
    public static partial int NCryptCreateProtectionDescriptor(
        [MarshalAs(UnmanagedType.LPWStr)] string? pwszDescriptorString,
        int dwFlags,
        out IntPtr phDescriptor);

    [LibraryImport("ncrypt.dll")]
    public static partial int NCryptCloseProtectionDescriptor(IntPtr hDescriptor);

    [LibraryImport("ncrypt.dll")]
    public static partial int NCryptQueryProtectionDescriptorName(
        [MarshalAs(UnmanagedType.LPWStr)] string? pwszName,
        [MarshalAs(UnmanagedType.LPWStr)] string? pwszDescriptorString,
        ref uint pcDescriptorString,
        int dwFlags);

    [LibraryImport("ncrypt.dll")]
    public static partial int NCryptRegisterProtectionDescriptorName(
        [MarshalAs(UnmanagedType.LPWStr)] string? pwszName,
        IntPtr pwszDescriptorString,
        int dwFlags);

    [LibraryImport("ncrypt.dll")]
    public static partial int NCryptProtectSecret(
        IntPtr hDescriptor,
        int dwFlags,
        IntPtr pbData,
        uint cbData,
        [Optional] in NCRYPT_ALLOC_PARA pMemPara,
        [Optional] IntPtr hWnd,
        out IntPtr ppbProtectedBlob,
        out uint pcbProtectedBlob);
    
    [LibraryImport("ncrypt.dll")]
    public static partial int NCryptProtectSecret(
        IntPtr hDescriptor,
        int dwFlags,
        IntPtr pbData,
        uint cbData,
        [Optional] IntPtr pMemPara,
        [Optional] IntPtr hWnd,
        out IntPtr ppbProtectedBlob,
        out uint pcbProtectedBlob);
    
    [LibraryImport("ncrypt.dll")]
    public static partial int NCryptUnprotectSecret(
        out IntPtr phDescriptor,
        int dwFlags,
        IntPtr pbProtectedBlob,
        uint cbProtectedBlob,
        [Optional] in NCRYPT_ALLOC_PARA pMemPara,
        [Optional] IntPtr hWnd,
        out IntPtr ppbData,
        out uint pcbData);
    
    [LibraryImport("ncrypt.dll")]
    public static partial int NCryptUnprotectSecret(
        out IntPtr phDescriptor,
        int dwFlags,
        IntPtr pbProtectedBlob,
        uint cbProtectedBlob,
        [Optional] IntPtr pMemPara,
        [Optional] IntPtr hWnd,
        out IntPtr ppbData,
        out uint pcbData);

    [LibraryImport("ncrypt.dll")]
    public static partial int NCryptStreamOpenToProtect(
        IntPtr hDescriptor,
        int dwFlags,
        [Optional] IntPtr hWnd,
        in NCRYPT_PROTECT_STREAM_INFO pStreamInfo,
        out IntPtr phStream);

    [LibraryImport("ncrypt.dll")]
    public static partial int NCryptStreamOpenToUnprotect(
        in NCRYPT_PROTECT_STREAM_INFO pStreamInfo,
        int dwFlags,
        [Optional] IntPtr hWnd,
        out IntPtr phStream);

    [LibraryImport("ncrypt.dll")]
    public static partial int NCryptStreamOpenToUnprotectEx(
        in NCRYPT_PROTECT_STREAM_INFO_EX pStreamInfo,
        int dwFlags,
        [Optional] IntPtr hWnd,
        out IntPtr phStream);

    [LibraryImport("ncrypt.dll")]
    public static partial int NCryptStreamUpdate(
        IntPtr hStream,
        IntPtr pbData,
        UIntPtr cbData, 
        [MarshalAs(UnmanagedType.Bool)] bool fFinal);
    
    [LibraryImport("ncrypt.dll")]
    public static partial int NCryptStreamClose(IntPtr hStream);
}