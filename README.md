# Switch-Binja-Loader
### Author: **EliseZeroTwo**

Work In Progress Binary Ninja Loader for common Nintendo Switch binaries

![Image demoing SMO in Binja](https://github.com/EliseZeroTwo/Switch-Binja-Loader/blob/master/images/home.png)

### Currently Supports
- NSO
- KIP

## Credits
- [ReSwitched for their nxo64.py loader](https://github.com/reswitched/loaders/blob/master/nxo64.py)
- [Adubbz for his Ghidra Switch Loader](https://github.com/Adubbz/Ghidra-Switch-Loader)
- [SwitchBrew](https://switchbrew.org/)

## Installation Instructions

Install all needed packages from pip in requirements.txt (Windows and MacOS Binja ship with an embedded python, [read here on how the docs say to install pip packages](https://docs.binary.ninja/guide/plugins.html#installing-prerequisites), or what I reccomend doing is just changing the python interpreter to a system install of python3 in settings)
### Windows

Clone this repository into `%APPDATA%/Binary Ninja/plugins/`

### Darwin

Clone this repository into `~/Library/Application Support/Binary Ninja/plugins/`

### Linux

Clone this repository into `~/.binaryninja/plugins/`
## Minimum Version

Binary Ninja v1200



## License

This plugin is released under the [ISC license](https://github.com/EliseZeroTwo/Switch-Binja-Loader/blob/master/LICENSE.txt)

## Metadata Version

2
