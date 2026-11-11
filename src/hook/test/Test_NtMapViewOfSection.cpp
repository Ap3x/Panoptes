// Tests the Hooked_NtMapViewOfSection and Hooked_NtMapViewOfSectionEx post-call check: a
// successful map into another process is reported with the API, the base and size the kernel
// returned, the requested protection, whether any page of the new view is executable, and
// whether it is an image. Maps into the current process are not reported.
#include "hook_test_sections.hpp"

static const std::vector<HookTestCase> g_Cases = {
	// NtMapViewOfSection

	{
		"RWX view mapped into remote process",
		[](HookTestContext& context) {
			MapView(CreatePageSection(PAGE_EXECUTE_READWRITE), context.RemoteProcess(), PAGE_EXECUTE_READWRITE);
		},
		{ "NtMapViewOfSection: 4096-byte view mapped into a remote process at * (protection 0x40, executable)" },
	},
	{
		"RX view mapped into remote process",
		[](HookTestContext& context) {
			MapView(CreatePageSection(PAGE_EXECUTE_READWRITE), context.RemoteProcess(), PAGE_EXECUTE_READ);
		},
		{ "NtMapViewOfSection: 4096-byte view mapped into a remote process at * (protection 0x20, executable)" },
	},
	{
		// The executable flag comes from the view's pages, not the section's maximum protection
		"RW view of an RWX section mapped into remote process",
		[](HookTestContext& context) {
			MapView(CreatePageSection(PAGE_EXECUTE_READWRITE), context.RemoteProcess(), PAGE_READWRITE);
		},
		{ "NtMapViewOfSection: 4096-byte view mapped into a remote process at * (protection 0x4, not executable)" },
	},
	{
		"RW view mapped into remote process",
		[](HookTestContext& context) {
			MapView(CreatePageSection(PAGE_READWRITE), context.RemoteProcess(), PAGE_READWRITE);
		},
		{ "NtMapViewOfSection: 4096-byte view mapped into a remote process at * (protection 0x4, not executable)" },
	},
	{
		// An image's first page is its read-only header; the code section further in is executable
		"Image mapped into remote process",
		[](HookTestContext& context) {
			MapView(CreateImageSection(), context.RemoteProcess(), PAGE_READONLY);
		},
		{ "NtMapViewOfSection: *-byte image mapped into a remote process at * (protection 0x2, executable)" },
	},
	{
		"RWX view mapped into current process is not reported",
		[](HookTestContext&) {
			MapView(CreatePageSection(PAGE_EXECUTE_READWRITE), GetCurrentProcess(), PAGE_EXECUTE_READWRITE);
		},
		{},
	},
	{
		"RWX view mapped through a real handle to self is not reported",
		[](HookTestContext&) {
			HANDLE self = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
			MapView(CreatePageSection(PAGE_EXECUTE_READWRITE), self, PAGE_EXECUTE_READWRITE);
			CloseHandle(self);
		},
		{},
	},
	{
		"Image mapped into current process is not reported",
		[](HookTestContext&) {
			MapView(CreateImageSection(), GetCurrentProcess(), PAGE_READONLY);
		},
		{},
	},
	{
		// The view asks for more than the section allows, so the map fails
		"Failed map into remote process is not reported",
		[](HookTestContext& context) {
			MapView(CreatePageSection(PAGE_READWRITE), context.RemoteProcess(), PAGE_EXECUTE_READWRITE);
		},
		{},
	},
	{
		"Map through a remote handle without PROCESS_VM_OPERATION is not reported",
		[](HookTestContext& context) {
			HANDLE remote = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetProcessId(context.RemoteProcess()));
			MapView(CreatePageSection(PAGE_EXECUTE_READWRITE), remote, PAGE_EXECUTE_READWRITE);
			CloseHandle(remote);
		},
		{},
	},

	// NtMapViewOfSectionEx

	{
		"Ex: RWX view mapped into remote process",
		[](HookTestContext& context) {
			MapViewEx(CreatePageSection(PAGE_EXECUTE_READWRITE), context.RemoteProcess(), PAGE_EXECUTE_READWRITE);
		},
		{ "NtMapViewOfSectionEx: 4096-byte view mapped into a remote process at * (protection 0x40, executable)" },
	},
	{
		"Ex: image mapped into remote process",
		[](HookTestContext& context) {
			MapViewEx(CreateImageSection(), context.RemoteProcess(), PAGE_READONLY);
		},
		{ "NtMapViewOfSectionEx: *-byte image mapped into a remote process at * (protection 0x2, executable)" },
	},
	{
		"Ex: RWX view mapped into current process is not reported",
		[](HookTestContext&) {
			MapViewEx(CreatePageSection(PAGE_EXECUTE_READWRITE), GetCurrentProcess(), PAGE_EXECUTE_READWRITE);
		},
		{},
	},
	{
		"Ex: failed map into remote process is not reported",
		[](HookTestContext& context) {
			MapViewEx(CreatePageSection(PAGE_READWRITE), context.RemoteProcess(), PAGE_EXECUTE_READWRITE);
		},
		{},
	},
};

int main(int argc, char** argv) {
	return RunHookTests(argc, argv, "NtMapViewOfSection", g_Cases);
}
