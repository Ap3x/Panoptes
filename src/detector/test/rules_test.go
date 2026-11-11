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
