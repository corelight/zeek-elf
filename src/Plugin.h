
#ifndef BRO_PLUGIN_BRO_ELF
#define BRO_PLUGIN_BRO_ELF

#include <plugin/Plugin.h>

namespace plugin {
namespace Zeek_ELF {

class Plugin : public ::plugin::Plugin
{
protected:
    // Overridden from plugin::Plugin.
    plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}

#endif
