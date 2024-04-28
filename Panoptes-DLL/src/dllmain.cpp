#include "framework.h"
#include "hook.hpp"
#include "vt_yara.hpp"

vt_yara obj;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		yr_initialize();
		yr_compiler_create(&(obj.compiler));
		vt_yara::CompileYaraRules(RULES_FOLDER, obj.compiler);
		if (yr_compiler_get_rules(obj.compiler, &(obj.rules)) != ERROR_SUCCESS)
		{
			yr_compiler_destroy(obj.compiler);
			printf("Error compiling Yara Rules");
			yr_finalize();
			exit(1);
		}

		hook::PlaceHooks(obj);
		break;
	case DLL_PROCESS_DETACH:
		hook::UnHook();
		yr_rules_destroy(obj.rules);
		yr_finalize();
		break;
	}
	return TRUE;
}

