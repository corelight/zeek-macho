
#ifndef BRO_PLUGIN_BRO_MACHO
#define BRO_PLUGIN_BRO_MACHO

#include <plugin/Plugin.h>

namespace plugin {
namespace Zeek_MACHO {

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
