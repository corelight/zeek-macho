
#include "Plugin.h"
#include "MACHO.h"

namespace plugin { namespace Bro_MACHO { Plugin plugin; } }

using namespace plugin::Bro_MACHO;

plugin::Configuration Plugin::Configure()
	{
    AddComponent(new ::file_analysis::Component("MACHO", ::file_analysis::MACHO::Instantiate));
	plugin::Configuration config;
	config.name = "Zeek::MACHO";
	config.description = "MACH-O File Analyzer";
	config.version.major = 0;
	config.version.minor = 1;
	return config;
	}
