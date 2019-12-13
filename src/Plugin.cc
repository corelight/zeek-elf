
#include "Plugin.h"
#include "ELF.h"

namespace plugin { namespace Zeek_ELF { Plugin plugin; } }

using namespace plugin::Zeek_ELF;

plugin::Configuration Plugin::Configure()
	{
    AddComponent(new ::file_analysis::Component("ELF", ::file_analysis::ELF::Instantiate));
	plugin::Configuration config;
	config.name = "Zeek::ELF";
	config.description = "ELF File Analyzer";
	config.version.major = 0;
	config.version.minor = 1;
    config.version.patch = 0;
	return config;
	}
