using System.Runtime.InteropServices;
using Xunit.Abstractions;

namespace PlainToolkit.CngProtectedData.Tests;

public class CngProtectedDataTests(ITestOutputHelper output)
{
    private void SkipIfNotWindows() =>
        Skip.IfNot(RuntimeInformation.IsOSPlatform(OSPlatform.Windows), "Only supported on Windows");
    
    [SkippableFact]
    public void CurrentUserTest()
    {
        SkipIfNotWindows();
        
        byte[] originalData = [1, 1, 4, 5, 1, 4];
        var scope = DataProtectionScope.CurrentUser;
        
        // 加密
        var encrypted = CngProtectedData.Protect(originalData, null, scope);
        // 解密
        var decrypted = CngProtectedData.Unprotect(encrypted, null, scope);
        
        output.WriteLine(BitConverter.ToString(originalData));
        output.WriteLine(BitConverter.ToString(encrypted));
        output.WriteLine(BitConverter.ToString(decrypted));
        
        Assert.NotNull(encrypted);
        Assert.NotEqual(originalData, encrypted);
        Assert.Equal(originalData, decrypted);
    }
    
    [SkippableFact]
    public void LocalMachineTest()
    {
        SkipIfNotWindows();
        
        byte[] originalData = [1, 1, 4, 5, 1, 4];
        var scope = DataProtectionScope.LocalMachine;
        
        // 加密
        var encrypted = CngProtectedData.Protect(originalData, null, scope);
        // 解密
        var decrypted = CngProtectedData.Unprotect(encrypted, null, scope);
        
        output.WriteLine(BitConverter.ToString(originalData));
        output.WriteLine(BitConverter.ToString(encrypted));
        output.WriteLine(BitConverter.ToString(decrypted));
        
        Assert.NotNull(encrypted);
        Assert.NotEqual(originalData, encrypted);
        Assert.Equal(originalData, decrypted);
    }
}