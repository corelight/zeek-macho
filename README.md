
# A Zeek Mach-o File Analysis Package

This package implements:

- Mach-o

## Building and Installing

This plugin can be built with:

```
./configure --zeek-dist=/your/zeek/src/dir
make
sudo make install
```

## Using MACHO

Once installed, this plugin can be loaded with the following Zeek script:

```
@load Zeek/MACHO

event file_macho_header(f: fa_file, m: Zeek::MACHOHeader)
    {
    print m;
    }
```

Enjoy!

## License:

This application(s) is/are covered by the Creative Commons BY-SA license.