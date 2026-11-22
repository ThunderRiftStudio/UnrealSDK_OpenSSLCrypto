using UnrealBuildTool;

public class OpenSSLCrypto : ModuleRules
{
	public OpenSSLCrypto(ReadOnlyTargetRules Target) : base(Target)
	{
		PCHUsage = ModuleRules.PCHUsageMode.UseExplicitOrSharedPCHs;

		PublicDependencyModuleNames.AddRange(new string[]
		{
			"Core",
			"CoreUObject",
			"Engine",
		});

		PrivateDependencyModuleNames.AddRange(new string[]
		{
			"OpenSSL",
		});

		// Bloquer openssl/ui.h (typedef UI entre en conflit avec namespace UI de Slate)
		// Guard exacte du fichier ui.h de UE5.5 OpenSSL 1.1.1t Win64
		PrivateDefinitions.Add("HEADER_UI_H");
		PrivateDefinitions.Add("OPENSSL_NO_UI_CONSOLE");
		PrivateDefinitions.Add("OPENSSL_NO_UI");

		if (Target.Platform == UnrealTargetPlatform.Win64)
		{
			PublicSystemLibraries.AddRange(new string[]
			{
				"crypt32.lib",
				"ws2_32.lib",
			});
		}
	}
}
