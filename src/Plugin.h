
#ifndef BRO_PLUGIN_BRO_ELF
#define BRO_PLUGIN_BRO_ELF

#include <zeek/plugin/Plugin.h>

namespace plugin {
namespace Zeek_ELF {

class Plugin : public zeek::plugin::Plugin
{
protected:
    // Overridden from plugin::Plugin.
    zeek::plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}

#endif
