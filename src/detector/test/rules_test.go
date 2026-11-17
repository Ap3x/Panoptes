package test

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Ap3x/Panoptes/detector/src/engine"
	"github.com/Ap3x/Panoptes/detector/src/rules"
)

type f = map[string]any

// Runs events (each 100ms apart) through every shipped rule and returns the names that fired,
// leaving out the generated LOLBAS rules (TestLolbasRules covers those)
func fired(t *testing.T, events ...f) []string {
	return firedWithPrefix(t, false, events...)
}

// firedWithPrefix returns the LOLBAS rules that fired when lolbas is true, the others otherwise
func firedWithPrefix(t *testing.T, lolbas bool, events ...f) []string {
	t.Helper()
	rs, err := rules.LoadDir("../rules")
	if err != nil {
		t.Fatal(err)
	}
	eng := engine.New(rs)
	start := time.Date(2026, 11, 10, 21, 5, 0, 0, time.UTC)
	var names []string
	for i, fields := range events {
		for _, m := range eng.Process(engine.Event{Seq: uint64(i + 1), Time: start.Add(time.Duration(i) * 100 * time.Millisecond), Fields: fields}) {
			if strings.HasPrefix(m.Rule.Name, "lolbas_") == lolbas {
				names = append(names, m.Rule.Name)
			}
		}
	}
	sort.Strings(names)
	return names
}

func TestShippedRules(t *testing.T) {
	const victim, injector = 1948.0, 13292.0
	cases := []struct {
		name   string
		events []f
		want   []string
	}{
		{"ImageBaseAddress written (x64)", []f{
			{"Event": "PEBWritten", "PID": injector, "TargetProcessId": victim, "Remote": true, "Size": 8.0, "PebOffset": "0x10"},
		}, []string{"peb_image_base_overwrite"}},
		{"ImageBaseAddress written (x86)", []f{
			{"Event": "PEBWritten", "PID": injector, "TargetProcessId": victim, "Remote": true, "Size": 4.0, "PebOffset": "0x8"},
		}, []string{"peb_image_base_overwrite"}},
		{"CreateProcess's own PEB writes are ignored", []f{
			{"Event": "PEBWritten", "PID": injector, "TargetProcessId": victim, "Remote": true, "Size": 8.0, "PebOffset": "0x2d8"},
			{"Event": "PEBWritten", "PID": injector, "TargetProcessId": victim, "Remote": true, "Size": 4.0, "PebOffset": "0x1e8"},
		}, nil},
		{"Unmap then write", []f{
			{"Event": "ExecutableUnmapped", "PID": injector, "TargetProcessId": victim, "Remote": true, "IsImage": true},
			{"Event": "PEWritten", "PID": injector, "TargetProcessId": victim, "Remote": true},
		}, []string{"remote_image_unmapped", "unmap_then_write_hollowing"}},
		{"Local unmap is not hollowing", []f{
			{"Event": "ExecutableUnmapped", "PID": injector, "TargetProcessId": injector, "Remote": false, "IsImage": true},
		}, nil},
		{"Early bird APC", []f{
			{"Event": "ProcessCreated", "PID": victim, "ParentPID": injector},
			{"Event": "ApcQueued", "PID": injector, "TargetProcessId": victim, "Remote": true},
		}, []string{"early_bird_apc"}},
		{"Section injection with a thread", []f{
			{"Event": "RemoteViewMapped", "PID": injector, "TargetProcessId": victim, "Remote": true, "Executable": true, "IsImage": false},
			{"Event": "RemoteThreadCreated", "PID": injector, "TargetProcessId": victim, "Remote": true},
		}, []string{"mapped_section_injection"}},
		{"Mapping an image view is not section injection", []f{
			{"Event": "RemoteViewMapped", "PID": injector, "TargetProcessId": victim, "Remote": true, "Executable": true, "IsImage": true},
			{"Event": "RemoteThreadCreated", "PID": injector, "TargetProcessId": victim, "Remote": true},
		}, nil},
		{"APC to a thread whose process could not be identified", []f{
			{"Event": "ApcQueued", "Source": "Hook", "PID": injector, "TargetProcessId": 0.0, "Remote": true, "TargetResolved": false},
		}, []string{"remote_target_unresolved"}},
		{"Resolved remote APC is not flagged as unresolved", []f{
			{"Event": "ApcQueued", "Source": "Hook", "PID": injector, "TargetProcessId": victim, "Remote": true, "TargetResolved": true},
		}, nil},
		{"BeingDebugged written", []f{
			{"Event": "PEBWritten", "PID": injector, "TargetProcessId": injector, "Remote": false, "Size": 1.0, "PebOffset": "0x2"},
		}, []string{"being_debugged_tampered"}},
		{"Protection set attempt", []f{
			{"Event": "ProtectionSetAttempt", "PID": injector, "TargetProcessId": victim, "Remote": true},
		}, []string{"process_protection_tamper"}},
		{"LSASS PEB read", []f{
			{"Event": "PEBRead", "PID": injector, "TargetProcessId": 700.0, "Remote": true, "TargetImage": `C:\Windows\System32\lsass.exe`},
		}, []string{"lsass_peb_read"}},
		{"Other remote PEB reads are ignored", []f{
			{"Event": "PEBRead", "PID": injector, "TargetProcessId": 700.0, "Remote": true, "TargetImage": `C:\Windows\explorer.exe`},
		}, nil},
		{"Remote PE made executable", []f{
			{"Event": "PEMadeExecutable", "PID": injector, "TargetProcessId": victim, "Remote": true},
		}, []string{"remote_pe_made_executable"}},
		{"vssadmin delete shadows", []f{
			{"Event": "ProcessCreated", "PID": victim, "Image": `\??\C:\Windows\System32\vssadmin.exe`, "CommandLine": `vssadmin.exe Delete Shadows /All /Quiet`},
		}, []string{"shadow_copy_deletion"}},
		{"wmic shadowcopy delete", []f{
			{"Event": "ProcessCreated", "PID": victim, "Image": `\??\C:\Windows\System32\wbem\WMIC.exe`, "CommandLine": `wmic shadowcopy delete`},
		}, []string{"shadow_copy_deletion"}},
		{"vssadmin list shadows is fine", []f{
			{"Event": "ProcessCreated", "PID": victim, "Image": `\??\C:\Windows\System32\vssadmin.exe`, "CommandLine": `vssadmin list shadows`},
		}, nil},
		{"Encoded PowerShell", []f{
			{"Event": "ProcessCreated", "PID": victim, "Image": `\??\C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				"CommandLine": `powershell.exe -NoP -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=`},
		}, []string{"encoded_powershell"}},
		{"PowerShell -ExecutionPolicy is not an encoded command", []f{
			{"Event": "ProcessCreated", "PID": victim, "Image": `\??\C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				"CommandLine": `powershell.exe -ExecutionPolicy Bypass -File C:\scripts\build-everything-now.ps1`},
		}, nil},
		{"Defender real-time protection off", []f{
			{"Event": "ProcessCreated", "PID": victim, "Image": `\??\C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				"CommandLine": `powershell Set-MpPreference -DisableRealtimeMonitoring $true`},
		}, []string{"defender_disabled"}},
		{"Defender turned back on is fine", []f{
			{"Event": "ProcessCreated", "PID": victim, "Image": `\??\C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				"CommandLine": `powershell Set-MpPreference -DisableRealtimeMonitoring $false`},
		}, nil},
		{"wevtutil cl", []f{
			{"Event": "ProcessCreated", "PID": victim, "Image": `\??\C:\Windows\System32\wevtutil.exe`, "CommandLine": `wevtutil.exe cl Security`},
		}, []string{"event_log_cleared"}},
		{"wevtutil query is fine", []f{
			{"Event": "ProcessCreated", "PID": victim, "Image": `\??\C:\Windows\System32\wevtutil.exe`, "CommandLine": `wevtutil.exe qe Security /c:5`},
		}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := fired(t, c.events...)
			if len(got) != len(c.want) {
				t.Fatalf("fired %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("fired %v, want %v", got, c.want)
				}
			}
		})
	}
}

func TestRegistryRules(t *testing.T) {
	const pid = 4242.0
	const sid = `S-1-5-21-1111111111-2222222222-3333333333-1001`
	const malware = `C:\Users\bob\AppData\Local\Temp\x.exe`
	set := func(image, key, valueName string, data any) f {
		return f{"Event": "RegistrySetValue", "PID": pid, "Image": image, "Key": key, "ValueName": valueName, "Data": data}
	}
	cases := []struct {
		name   string
		events []f
		want   []string
	}{
		{"Run key", []f{set(malware, `HKU\`+sid+`\Software\Microsoft\Windows\CurrentVersion\Run`, "Updater", malware)},
			[]string{"registry_run_key_persistence"}},
		{"WOW64 RunOnce", []f{set(malware, `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`, "x", malware)},
			[]string{"registry_run_key_persistence"}},
		{"A key named like Run is not Run", []f{set(malware, `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunNotification`, "x", malware)},
			nil},
		{"Winlogon shell replaced", []f{set(malware, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "Shell", "explorer.exe, "+malware)},
			[]string{"registry_winlogon_persistence"}},
		{"Winlogon defaults rewritten", []f{
			set(`C:\Windows\System32\svchost.exe`, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "Shell", "explorer.exe"),
			set(`C:\Windows\System32\svchost.exe`, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "Userinit", `C:\Windows\system32\userinit.exe,`),
		}, nil},
		{"IFEO debugger", []f{set(malware, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe`, "Debugger", `C:\Windows\System32\cmd.exe`)},
			[]string{"registry_ifeo_debugger"}},
		{"IFEO mitigation options are fine", []f{set(malware, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\app.exe`, "MitigationOptions", "0011")},
			nil},
		{"Silent process exit", []f{
			set(malware, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe`, "GlobalFlag", 512.0),
			set(malware, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe`, "MonitorProcess", malware),
		}, []string{"registry_silent_process_exit", "registry_silent_process_exit"}},
		{"AppInit_DLLs", []f{
			set(malware, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`, "AppInit_DLLs", `C:\x.dll`),
			set(malware, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`, "LoadAppInit_DLLs", 1.0),
		}, []string{"registry_appinit_dlls", "registry_appinit_dlls"}},
		{"Empty AppInit_DLLs is fine", []f{set(malware, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`, "AppInit_DLLs", "")},
			nil},
		{"COM hijack", []f{set(malware, `HKU\`+sid+`_Classes\CLSID\{BCDE0395-E52F-467C-8E3D-C4579291692E}\InprocServer32`, "", `C:\x.dll`)},
			[]string{"registry_com_hijack"}},
		{"Machine-wide COM registration is fine", []f{set(malware, `HKLM\SOFTWARE\Classes\CLSID\{BCDE0395-E52F-467C-8E3D-C4579291692E}\InprocServer32`, "", `C:\x.dll`)},
			nil},
		{"fodhelper UAC bypass", []f{
			set(malware, `HKU\`+sid+`_Classes\ms-settings\Shell\Open\command`, "DelegateExecute", ""),
			set(malware, `HKU\`+sid+`_Classes\ms-settings\Shell\Open\command`, "", malware),
		}, []string{"registry_uac_bypass", "registry_uac_bypass"}},
		{"LSA security package", []f{set(malware, `HKLM\SYSTEM\ControlSet001\Control\Lsa`, "Security Packages", []any{"kerberos", "msv1_0", "evil"})},
			[]string{"registry_lsa_package_added"}},
		{"RunAsPPL off", []f{set(malware, `HKLM\SYSTEM\ControlSet001\Control\Lsa`, "RunAsPPL", 0.0)},
			[]string{"registry_lsa_protection_weakened"}},
		{"RunAsPPL on is fine", []f{set(malware, `HKLM\SYSTEM\ControlSet001\Control\Lsa`, "RunAsPPL", 1.0)},
			nil},
		{"WDigest", []f{set(malware, `HKLM\SYSTEM\ControlSet001\Control\SecurityProviders\WDigest`, "UseLogonCredential", 1.0)},
			[]string{"registry_wdigest_enabled"}},
		{"Defender disabled by policy", []f{set(malware, `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`, "DisableAntiSpyware", 1.0)},
			[]string{"registry_defender_disabled"}},
		{"Defender real-time monitoring off", []f{set(malware, `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`, "DisableRealtimeMonitoring", 1.0)},
			[]string{"registry_defender_disabled"}},
		{"Defender exclusion", []f{set(`C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe`, `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`, `C:\Users\bob\AppData`, 0.0)},
			[]string{"registry_defender_exclusion_added"}},
		{"Service written directly", []f{set(malware, `HKLM\SYSTEM\ControlSet001\Services\evil`, "ImagePath", malware)},
			[]string{"registry_service_written_directly"}},
		{"Service installed by the SCM is fine", []f{set(`C:\Windows\System32\services.exe`, `HKLM\SYSTEM\ControlSet001\Services\good`, "ImagePath", `C:\good.exe`)},
			nil},
		{"Defender service disabled", []f{set(malware, `HKLM\SYSTEM\ControlSet001\Services\WinDefend`, "Start", 4.0)},
			[]string{"registry_security_service_disabled"}},
		{"Panoptes driver disabled", []f{set(malware, `HKLM\SYSTEM\ControlSet001\Services\Panoptes`, "Start", 4.0)},
			[]string{"registry_panoptes_tampered", "registry_security_service_disabled"}},
		{"Panoptes key deleted", []f{{"Event": "RegistryDeleteKey", "PID": pid, "Image": malware, "Key": `HKLM\SYSTEM\ControlSet001\Services\Panoptes`}},
			[]string{"registry_panoptes_tampered"}},
		{"SCM updating Panoptes is fine", []f{set(`C:\Windows\System32\services.exe`, `HKLM\SYSTEM\ControlSet001\Services\Panoptes`, "Start", 2.0)},
			nil},
		{`reg save HKLM\SAM`, []f{{"Event": "RegistrySaveKey", "PID": pid, "Image": `C:\Windows\System32\reg.exe`, "Key": `HKLM\SAM`, "Path": `C:\temp\sam`}},
			[]string{"registry_credential_hive_saved"}},
		{"Saving a software key is fine", []f{{"Event": "RegistrySaveKey", "PID": pid, "Image": `C:\Windows\System32\reg.exe`, "Key": `HKLM\SOFTWARE\Vendor`, "Path": `C:\temp\vendor.hiv`}},
			nil},
		{"SAM hashes read", []f{{"Event": "RegistryQueryValue", "PID": pid, "Image": malware, "Key": `HKLM\SAM\SAM\Domains\Account\Users\000001F4`, "ValueName": "V"}},
			[]string{"registry_credential_read"}},
		{"LSA secret read", []f{{"Event": "RegistryQueryValue", "PID": pid, "Image": malware, "Key": `HKLM\SECURITY\Policy\Secrets\DefaultPassword\CurrVal`, "ValueName": ""}},
			[]string{"registry_credential_read"}},
		{"lsass reading the SAM is fine", []f{{"Event": "RegistryQueryValue", "PID": 700.0, "Image": `C:\Windows\System32\lsass.exe`, "Key": `HKLM\SAM\SAM\Domains\Account\Users\000001F4`, "ValueName": "V"}},
			nil},
		{"Copied SAM loaded", []f{{"Event": "RegistryLoadKey", "PID": pid, "Image": malware, "Key": `HKLM\x`, "Path": `C:\temp\SAM`}},
			[]string{"registry_credential_hive_loaded"}},
		{"User profile loaded is fine", []f{{"Event": "RegistryLoadKey", "PID": 1200.0, "Image": `C:\Windows\System32\svchost.exe`, "Key": `HKU\` + sid, "Path": `C:\Users\bob\NTUSER.DAT`}},
			nil},
		{"Hive replaced", []f{{"Event": "RegistryReplaceKey", "PID": pid, "Image": malware, "Key": `HKLM\SOFTWARE`, "Path": `C:\temp\new`, "OldPath": `C:\temp\old`}},
			[]string{"registry_hive_replaced"}},
		{"Run key locked down", []f{{"Event": "RegistrySetKeySecurity", "PID": pid, "Image": malware, "Key": `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "Changed": []any{"Dacl"}}},
			[]string{"registry_persistence_key_permissions_changed"}},
		{"Permissions on an ordinary key are fine", []f{{"Event": "RegistrySetKeySecurity", "PID": pid, "Image": malware, "Key": `HKLM\SOFTWARE\Vendor`, "Changed": []any{"Dacl"}}},
			nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := fired(t, c.events...)
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Fatalf("fired %v, want %v", got, c.want)
			}
		})
	}
}
