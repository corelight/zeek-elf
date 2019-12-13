
# A Zeek ELF Package

This package implements:

- ELF

## Building and Installing

This plugin can be built with:

```
./configure --zeek-dist=/your/zeek/src/dir
make
sudo make install
```

## Using ELF

Once installed, this plugin can be loaded with the following Zeek script:

```
@load Zeek/ELF

event file_elf(f: fa_file)
    {
    print "ELF!";
    }

event file_elf_header(f: fa_file, m: Zeek::ELFHeader)
    {
    print "ELF HEADER!";
    print m;
    }
```

Enjoy!

## License:

This application(s) is/are covered by the Creative Commons BY-SA license.