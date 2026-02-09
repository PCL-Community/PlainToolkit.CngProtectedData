// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
//
// 代码修改自 System.Security.Cryptography.ProtectedData
// 源代码：https://github.com/dotnet/runtime/blob/main/src/libraries/System.Security.Cryptography.ProtectedData/src/System/Security/Cryptography/ProtectedData.cs

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using PlainToolkit.CngProtectedData.Native;

namespace PlainToolkit.CngProtectedData;

public static class CngProtectedData
{
    private static readonly byte[] s_nonEmpty = new byte[1];

    public static byte[] Protect(byte[] userData, byte[]? optionalEntropy, DataProtectionScope scope)
    {
        CheckPlatformSupport();

        ArgumentNullException.ThrowIfNull(userData);

        byte[]? outputData;
        bool result = TryProtectOrUnprotect(
            userData,
            optionalEntropy,
            scope,
            protect: true,
            allocateArray: true,
            bytesWritten: out _,
            outputData: out outputData);
        Debug.Assert(result);
        Debug.Assert(outputData != null);
        return outputData;
    }

#if NET
    /// <summary>
    /// Encrypts the data in a specified byte span and returns a byte array that contains the encrypted data.
    /// </summary>
    /// <param name="userData">A buffer that contains the data to encrypt.</param>
    /// <param name="scope">One of the enumeration values that specifies the scope of encryption.</param>
    /// <param name="optionalEntropy">
    /// An optional additional byte span used to increase the complexity of the encryption,
    /// or empty for no additional complexity.
    /// </param>
    /// <returns>A byte array representing the encrypted data.</returns>
    /// <exception cref="CryptographicException">The encryption failed.</exception>
    /// <exception cref="NotSupportedException">The operating system does not support this method.</exception>
    /// <exception cref="OutOfMemoryException">The system ran out of memory while encrypting the data.</exception>
    /// <exception cref="PlatformNotSupportedException">
    /// Calls to the Protect method are supported on Windows operating systems only.
    /// </exception>
    public static byte[] Protect(
        ReadOnlySpan<byte> userData,
        DataProtectionScope scope,
        ReadOnlySpan<byte> optionalEntropy = default)
    {
        CheckPlatformSupport();

        byte[]? outputData;
        bool result = TryProtectOrUnprotect(
            userData,
            optionalEntropy,
            scope,
            protect: true,
            allocateArray: true,
            bytesWritten: out _,
            outputData: out outputData);
        Debug.Assert(result);
        Debug.Assert(outputData != null);
        return outputData;
    }

    /// <summary>
    /// Encrypts the data in a specified buffer and writes the encrypted data to a destination buffer.
    /// </summary>
    /// <param name="userData">A buffer that contains data to encrypt.</param>
    /// <param name="scope">One of the enumeration values that specifies the scope of encryption.</param>
    /// <param name="destination">The buffer to receive the encrypted data.</param>
    /// <param name="bytesWritten">
    /// When this method returns, contains the number of bytes
    /// written to <paramref name="destination"/>.
    /// </param>
    /// <param name="optionalEntropy">
    /// An optional additional buffer used to increase the complexity of the encryption,
    /// or empty for no additional complexity.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if <paramref name="destination"/> was large enough to receive the decrypted data;
    /// otherwise, <see langword="false"/>.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// The buffer in <paramref name="destination"/> is too small to hold the encrypted data.
    /// </exception>
    /// <exception cref="CryptographicException">The encryption failed.</exception>
    /// <exception cref="NotSupportedException">The operating system does not support this method.</exception>
    /// <exception cref="OutOfMemoryException">The system ran out of memory while encrypting the data.</exception>
    /// <exception cref="PlatformNotSupportedException">
    /// Calls to the Protect method are supported on Windows operating systems only.
    /// </exception>
    public static bool TryProtect(
        ReadOnlySpan<byte> userData,
        DataProtectionScope scope,
        Span<byte> destination,
        out int bytesWritten,
        ReadOnlySpan<byte> optionalEntropy = default)
    {
        CheckPlatformSupport();

        return TryProtectOrUnprotect(
            userData,
            optionalEntropy,
            scope,
            protect: true,
            allocateArray: false,
            outputSpan: destination,
            bytesWritten: out bytesWritten,
            outputData: out _);
    }

    /// <summary>
    /// Encrypts the data in a specified buffer and writes the encrypted data to a destination buffer.
    /// </summary>
    /// <param name="userData">A buffer that contains data to encrypt.</param>
    /// <param name="scope">One of the enumeration values that specifies the scope of encryption.</param>
    /// <param name="destination">The buffer to receive the encrypted data.</param>
    /// <param name="optionalEntropy">
    /// An optional additional buffer used to increase the complexity of the encryption,
    /// or empty for no additional complexity.
    /// </param>
    /// <returns>The total number of bytes written to <paramref name="destination"/></returns>
    /// <exception cref="ArgumentException">
    /// The buffer in <paramref name="destination"/> is too small to hold the encrypted data.
    /// </exception>
    /// <exception cref="CryptographicException">The encryption failed.</exception>
    /// <exception cref="NotSupportedException">The operating system does not support this method.</exception>
    /// <exception cref="OutOfMemoryException">The system ran out of memory while encrypting the data.</exception>
    /// <exception cref="PlatformNotSupportedException">
    /// Calls to the Protect method are supported on Windows operating systems only.
    /// </exception>
    public static int Protect(
        ReadOnlySpan<byte> userData,
        DataProtectionScope scope,
        Span<byte> destination,
        ReadOnlySpan<byte> optionalEntropy = default)
    {
        CheckPlatformSupport();

        int bytesWritten;
        if (!TryProtectOrUnprotect(
                userData,
                optionalEntropy,
                scope,
                protect: true,
                allocateArray: false,
                outputSpan: destination,
                bytesWritten: out bytesWritten,
                outputData: out _))
        {
            throw new ArgumentException("Destination is too short.", nameof(destination));
        }

        return bytesWritten;
    }
#endif

    public static byte[] Unprotect(byte[] encryptedData, byte[]? optionalEntropy, DataProtectionScope scope)
    {
        CheckPlatformSupport();

        ArgumentNullException.ThrowIfNull(encryptedData);

        byte[]? outputData;
        bool result = TryProtectOrUnprotect(
            encryptedData,
            optionalEntropy,
            scope,
            protect: false,
            allocateArray: true,
            bytesWritten: out _,
            outputData: out outputData);

        Debug.Assert(result);
        Debug.Assert(outputData != null);
        return outputData;
    }

#if NET
    /// <summary>
    /// Decrypts the data in a specified byte array and returns a byte array that contains the decrypted data.
    /// </summary>
    /// <param name="encryptedData">A buffer that contains data to decrypt.</param>
    /// <param name="scope">One of the enumeration values that specifies the scope of encryption.</param>
    /// <param name="optionalEntropy">
    /// An optional additional buffer used to increase the complexity of the encryption,
    /// or empty for no additional complexity.
    /// </param>
    /// <returns>A byte array representing the encrypted data.</returns>
    /// <exception cref="CryptographicException">The encryption failed.</exception>
    /// <exception cref="NotSupportedException">The operating system does not support this method.</exception>
    /// <exception cref="OutOfMemoryException">The system ran out of memory while decrypting the data.</exception>
    /// <exception cref="PlatformNotSupportedException">
    /// Calls to the Unprotect method are supported on Windows operating systems only.
    /// </exception>
    public static byte[] Unprotect(
        ReadOnlySpan<byte> encryptedData,
        DataProtectionScope scope,
        ReadOnlySpan<byte> optionalEntropy = default)
    {
        CheckPlatformSupport();

        byte[]? outputData;
        bool result = TryProtectOrUnprotect(
            encryptedData,
            optionalEntropy,
            scope,
            protect: false,
            allocateArray: true,
            bytesWritten: out _,
            outputData: out outputData);

        Debug.Assert(result);
        Debug.Assert(outputData != null);
        return outputData;
    }

    /// <summary>
    /// Decrypts the data in a specified buffer and writes the decrypted data to a destination buffer.
    /// </summary>
    /// <param name="encryptedData">A buffer that contains data to decrypt.</param>
    /// <param name="scope">One of the enumeration values that specifies the scope of encryption.</param>
    /// <param name="destination">The buffer to receive the decrypted data.</param>
    /// <param name="bytesWritten">
    /// When this method returns, contains the number of bytes
    /// written to <paramref name="destination"/>.
    /// </param>
    /// <param name="optionalEntropy">
    /// An optional additional buffer used to increase the complexity of the encryption,
    /// or empty for no additional complexity.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if <paramref name="destination"/> was large enough to receive the decrypted data;
    /// otherwise, <see langword="false"/>.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// The buffer in <paramref name="destination"/> is too small to hold the decrypted data.
    /// </exception>
    /// <exception cref="CryptographicException">The encryption failed.</exception>
    /// <exception cref="NotSupportedException">The operating system does not support this method.</exception>
    /// <exception cref="OutOfMemoryException">The system ran out of memory while encrypting the data.</exception>
    /// <exception cref="PlatformNotSupportedException">
    /// Calls to the Unprotect method are supported on Windows operating systems only.
    /// </exception>
    public static bool TryUnprotect(
        ReadOnlySpan<byte> encryptedData,
        DataProtectionScope scope,
        Span<byte> destination,
        out int bytesWritten,
        ReadOnlySpan<byte> optionalEntropy = default)
    {
        CheckPlatformSupport();

        return TryProtectOrUnprotect(
            encryptedData,
            optionalEntropy,
            scope,
            protect: false,
            allocateArray: false,
            outputSpan: destination,
            bytesWritten: out bytesWritten,
            outputData: out _);
    }

    /// <summary>
    /// Decrypts the data in a specified buffer and writes the decrypted data to a destination buffer.
    /// </summary>
    /// <param name="encryptedData">A buffer that contains data to decrypt.</param>
    /// <param name="scope">One of the enumeration values that specifies the scope of encryption.</param>
    /// <param name="destination">The buffer to receive the decrypted data.</param>
    /// <param name="optionalEntropy">
    /// An optional additional buffer used to increase the complexity of the encryption,
    /// or empty for no additional complexity.
    /// </param>
    /// <returns>The total number of bytes written to <paramref name="destination"/></returns>
    /// <exception cref="ArgumentException">
    /// The buffer in <paramref name="destination"/> is too small to hold the decrypted data.
    /// </exception>
    /// <exception cref="CryptographicException">The encryption failed.</exception>
    /// <exception cref="NotSupportedException">The operating system does not support this method.</exception>
    /// <exception cref="OutOfMemoryException">The system ran out of memory while encrypting the data.</exception>
    /// <exception cref="PlatformNotSupportedException">
    /// Calls to the Unprotect method are supported on Windows operating systems only.
    /// </exception>
    public static int Unprotect(
        ReadOnlySpan<byte> encryptedData,
        DataProtectionScope scope,
        Span<byte> destination,
        ReadOnlySpan<byte> optionalEntropy = default)
    {
        CheckPlatformSupport();

        int bytesWritten;
        if (!TryProtectOrUnprotect(
                encryptedData,
                optionalEntropy,
                scope,
                protect: false,
                allocateArray: false,
                outputSpan: destination,
                bytesWritten: out bytesWritten,
                outputData: out _))
        {
            throw new ArgumentException("Destination is too short.", nameof(destination));
        }

        return bytesWritten;
    }
#endif

    private static bool TryProtectOrUnprotect(
        ReadOnlySpan<byte> inputData,
        ReadOnlySpan<byte> optionalEntropy,
        DataProtectionScope scope,
        bool protect,
        out int bytesWritten,
        out byte[]? outputData,
        bool allocateArray,
        Span<byte> outputSpan = default)
    {
        if (!optionalEntropy.IsEmpty)
        {
            // TODO: 支持可选熵
            throw new PlatformNotSupportedException("CNG DPAPI with LOCAL providers does not support optional entropy.");
        }

        var descriptorRule = scope switch
        {
            DataProtectionScope.CurrentUser => "LOCAL=user",
            DataProtectionScope.LocalMachine => "LOCAL=machine",
            _ => throw new ArgumentException("Invalid DataProtectionScope", nameof(scope))
        };
        
        unsafe
        {
            var relevantData = inputData.IsEmpty ? s_nonEmpty : inputData;

            fixed (byte* pInputData = relevantData)
            {
                int hresult;
                var hDescriptor = IntPtr.Zero;
                var pbOutput = IntPtr.Zero;
                uint cbOutput;
                
                try
                {
                    if (protect)
                    {
                        // 创建保护描述符
                        hresult = NCryptProtect.NCryptCreateProtectionDescriptor(descriptorRule, 0, out hDescriptor);
                        if (hresult != 0)
                        {
                            throw new CryptographicException($"NCryptCreateProtectionDescriptor failed: {hresult:X}");
                        }
                        
                        // Protect
                        hresult = NCryptProtect.NCryptProtectSecret(
                            hDescriptor,
                            0,
                            (IntPtr)pInputData,
                            (uint)relevantData.Length,
                            IntPtr.Zero,
                            IntPtr.Zero,
                            out pbOutput,
                            out cbOutput);
                    }
                    else
                    {
                        // Unprotect
                        hresult = NCryptProtect.NCryptUnprotectSecret(
                            out hDescriptor,
                            0,
                            (IntPtr)pInputData,
                            (uint)relevantData.Length,
                            IntPtr.Zero,
                            IntPtr.Zero,
                            out pbOutput,
                            out cbOutput);
                    }

                    if (hresult != 0)
                    {
                        throw new CryptographicException($"{(protect ? "Protect" : "Unprotect")} failed: {hresult:X}");
                    }
                    
                    var length = (int)cbOutput;

                    // 分配新数组
                    if (allocateArray)
                    {
                        outputData = new byte[length];
                        Marshal.Copy(pbOutput, outputData, 0, length);
                        bytesWritten = length;
                        return true;
                    }
                    
                    // 如果不分配新数组，则写入目标缓冲区
                    outputData = null;
                    // 判断输出缓冲区是否足够大
                    if (length > outputSpan.Length)
                    {
                        bytesWritten = 0;
                        return false;
                    }

                    // 从内存拷贝到目标缓冲区
                    new ReadOnlySpan<byte>((void*)pbOutput, length).CopyTo(outputSpan);
                    bytesWritten = length;
                    return true;
                }
                finally
                {
                    // 清理资源
                    if (pbOutput != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(pbOutput);
                    }
                    
                    // 关闭保护描述符
                    if (hDescriptor != IntPtr.Zero)
                    {
                        hresult = NCryptProtect.NCryptCloseProtectionDescriptor(hDescriptor);
                        if (hresult != 0)
                        {
                            Debug.Fail($"NCryptCloseProtectionDescriptor failed: {hresult:X}");
                        }
                    }
                }
            }
        }
    }

    private static void CheckPlatformSupport()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            throw new PlatformNotSupportedException();
        }
    }
}