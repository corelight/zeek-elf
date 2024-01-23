
#include "Plugin.h"
#include "elf.h"

namespace plugin { namespace Zeek_ELF { Plugin plugin; } }

using namespace plugin::Zeek_ELF;

zeek::plugin::Configuration Plugin::Configure()
    {
    AddComponent(new zeek::file_analysis::Component("ELF", ::file_analysis::ELF::Instantiate));
    zeek::plugin::Configuration config;
    config.name = "Zeek::ELF";
    config.description = "ELF File Analyzer";
    config.version.major = 0;
    config.version.minor = 1;
    config.version.patch = 0;
    return config;
    }
