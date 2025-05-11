# AI Generated Microsoft Uncocker

A tool to uncock Microsoft VS Code extensions for vscode forks by patching cock checks.

- C# for Visual Studio Code - ms-dotnettools.csharp
- C/C++ for Visual Studio Code - ms-vscode.cpptools

# Ever seen this? Well no more!

- The C/C++ extension may be used only with Microsoft Visual Studio, Visual Studio for Mac, Visual Studio Code, Azure DevOps, Team Foundation Server, and successor Microsoft products and services to develop and test your applications.
- Unable to start debugging. .NET Debugging is supported only in Microsoft versions of VS Code. See https://aka.ms/VSCode-DotNet-DbgLicense for more information

## Usage

```bash
python uncocker.py <path-to-extension.vsix>
```

### The tool will:
1. Unpack the .vsix archive
2. Parse the extension manifest to detect the target platform
3. Patch the cock checks in the binaries
4. Repack the modified files into a new .vsix archive

#### How to install modified extension:
1. Open your VS Code fork of choice
2. Uninstall the original extension
3. Ctrl+Shift+P -> Install from VSIX
4. Select the modified .vsix file

## Architecture Support

| Architecture | C# for Visual Studio Code | C/C++ for Visual Studio Code | Signatures    |
|--------------|---------------------------|------------------------------|---------------|
| win32-x64    | TESTED                    | TESTED                       | STABLE        |
| win32-arm64  | UNTESTED                  | UNTESTED                     | UNSTABLE      |
| linux-x64    | TESTED                    | TESTED                       | STABLE        |
| linux-arm64  | UNTESTED                  | UNTESTED                     | UNSTABLE      |
| linux-armhf  | UNTESTED                  | UNTESTED                     | UNSTABLE      |
| darwin-x64   | UNTESTED                  | UNTESTED                     | UNSTABLE      |
| darwin-arm64 | UNTESTED                  | UNTESTED                     | UNSTABLE      |
| alpine-x64   | TESTED                    | TESTED                       | STABLE        |
| alpine-arm64 | UNTESTED                  | UNTESTED                     | UNSTABLE      |

- ms-dotnettools.csharp - version 2.63.32
- ms-vscode.cpptools - version 1.25.3

## Warning

This tool is written by an AI, it may not work as expected.

## Credits

- [Ouroboros](https://gist.github.com/Ouroboros/1a1e0b9c8bcbac2a519516aa5a12a52b)

## License

```
          DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
                  Version 2, December 2004

Copyright (C) 2025 cursor ai <cursor.com>

Everyone is permitted to copy and distribute verbatim or modified
copies of this license document, and changing it is allowed as long
as the name is changed.

          DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

0. You just DO WHAT THE FUCK YOU WANT TO.
1. I HATE AI I HATE AI I HATE AI I HATE AI I HATE AI.
```
