
#include "Plugin.h"
#include "MACHO.h"

namespace plugin { namespace Zeek_MACHO { Plugin plugin; } }

using namespace plugin::Zeek_MACHO;

plugin::Configuration Plugin::Configure()
    {
    AddComponent(new ::file_analysis::Component("MACHO", ::file_analysis::MACHO::Instantiate));
    plugin::Configuration config;
    config.name = "Zeek::MACHO";
    config.description = "MACH-O File Analyzer";
    config.version.major = 0;
    config.version.minor = 1;
    config.version.patch = 0;
    return config;
    }
