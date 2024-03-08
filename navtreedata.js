/*
 @licstart  The following is the entire license notice for the JavaScript code in this file.

 The MIT License (MIT)

 Copyright (C) 1997-2020 by Dimitri van Heesch

 Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 and associated documentation files (the "Software"), to deal in the Software without restriction,
 including without limitation the rights to use, copy, modify, merge, publish, distribute,
 sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all copies or
 substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 @licend  The above is the entire license notice for the JavaScript code in this file
*/
var NAVTREE =
[
  [ "CryptoAuthLib", "index.html", [
    [ "CryptoAuthLib - Microchip CryptoAuthentication Library", "index.html", "index" ],
    [ "License", "a02789.html", null ],
    [ "IP Protection with Symmetric Authentication", "a02790.html", [
      [ "User Considerations", "a02790.html#autotoc_md0", null ],
      [ "Examples", "a02790.html#autotoc_md1", null ]
    ] ],
    [ "PKCS11 Application Information", "a02791.html", [
      [ "Setting up cryptoauthlib as a PKCS11 Provider for your system (LINUX)", "a02791.html#autotoc_md2", [
        [ "Update libp11 on the system. The version should be at minimum 0.4.10", "a02791.html#autotoc_md3", null ],
        [ "Build and Install cryptoauthlib with PKCS11 support", "a02791.html#autotoc_md4", null ],
        [ "Configuring the cryptoauthlib PKCS11 library", "a02791.html#autotoc_md5", [
          [ "cryptoauthlib.conf", "a02791.html#autotoc_md6", null ],
          [ "slot.conf.tmpl", "a02791.html#autotoc_md7", [
            [ "interface", "a02791.html#autotoc_md8", null ],
            [ "freeslots", "a02791.html#autotoc_md9", null ]
          ] ]
        ] ],
        [ "Using p11-kit-proxy", "a02791.html#autotoc_md10", null ],
        [ "Without using p11-kit-proxy", "a02791.html#autotoc_md11", null ],
        [ "Testing", "a02791.html#autotoc_md12", null ]
      ] ]
    ] ],
    [ "Application Support", "a02792.html", null ],
    [ "Secure boot using ATECC608", "a02793.html", [
      [ "Implementation Considerations", "a02793.html#autotoc_md13", null ],
      [ "Examples", "a02793.html#autotoc_md14", null ]
    ] ],
    [ "Contribution Guidelines", "a02795.html", [
      [ "Cryptoauthlib HAL Architecture", "a01410.html#autotoc_md16", null ],
      [ "CryptoAuthLib Supported HAL Layers", "a01410.html#autotoc_md18", [
        [ "Microchip Harmony 3 for all PIC32 & ARM products - Use the Harmony 3 Configurator to generate and configure prjects", "a01410.html#autotoc_md19", null ],
        [ "Microchip 8 & 16 bit products - AVR, PIC16/18, PIC24/DSPIC", "a01410.html#autotoc_md20", null ],
        [ "OS & RTOS integrations", "a01410.html#autotoc_md21", null ],
        [ "Legacy Support - <a href=\"https://www.microchip.com/start\" >Atmel START</a> for AVR, ARM based processesors (SAM)", "a01410.html#autotoc_md22", null ],
        [ "Legacy Support - ASF3 for ARM Cortex-m0 & Cortex-m based processors (SAM)", "a01410.html#autotoc_md23", null ]
      ] ]
    ] ],
    [ "openssl directory - Purpose", "a02800.html", null ],
    [ "Python CryptoAuthLib module", "a02801.html", [
      [ "Introduction", "a02801.html#autotoc_md25", [
        [ "Code Examples", "a02801.html#autotoc_md26", null ]
      ] ],
      [ "Installation", "a02801.html#autotoc_md27", [
        [ "CryptoAuthLib python module can be installed through Python's pip tool:", "a02801.html#autotoc_md28", null ],
        [ "To upgrade your installation when new releases are made:", "a02801.html#autotoc_md29", null ],
        [ "If you ever need to remove your installation:", "a02801.html#autotoc_md30", null ]
      ] ],
      [ "What does python CryptoAuthLib package do?", "a02801.html#autotoc_md31", null ],
      [ "Supported hardware", "a02801.html#autotoc_md32", null ],
      [ "Supported devices", "a02801.html#autotoc_md33", null ],
      [ "Using cryptoauthlib python module", "a02801.html#autotoc_md34", null ],
      [ "In Summary", "a02801.html#autotoc_md35", [
        [ "Step I: Import the module", "a02801.html#autotoc_md36", null ],
        [ "Step II: Initilize the module", "a02801.html#autotoc_md37", null ],
        [ "Step III: Use Cryptoauthlib APIs", "a02801.html#autotoc_md38", null ]
      ] ],
      [ "Code portability", "a02801.html#autotoc_md39", null ],
      [ "Cryptoauthlib module API documentation", "a02801.html#autotoc_md40", [
        [ "help() command", "a02801.html#autotoc_md41", null ],
        [ "dir() command", "a02801.html#autotoc_md42", null ]
      ] ],
      [ "Code Examples", "a02801.html#autotoc_md43", null ],
      [ "Tests", "a02801.html#autotoc_md44", null ],
      [ "Release notes", "a02801.html#autotoc_md45", null ]
    ] ],
    [ "Python CryptoAuthLib Module Testing", "a02802.html", [
      [ "Introduction", "a02802.html#autotoc_md47", [
        [ "Running", "a02802.html#autotoc_md48", null ],
        [ "Test options", "a02802.html#autotoc_md49", null ]
      ] ]
    ] ],
    [ "Microchip Cryptoauthlib Release Notes", "a02803.html", [
      [ "Release v3.7.4 (03/08/2024)", "a02803.html#autotoc_md61", [
        [ "New Features", "a02803.html#autotoc_md62", null ],
        [ "Fixes", "a02803.html#autotoc_md63", null ]
      ] ],
      [ "Release v3.7.3 (01/31/2024)", "a02803.html#autotoc_md64", [
        [ "New Features", "a02803.html#autotoc_md65", null ],
        [ "Fixes", "a02803.html#autotoc_md66", null ]
      ] ],
      [ "Release v3.7.2 (01/19/2024)", "a02803.html#autotoc_md67", [
        [ "New Features", "a02803.html#autotoc_md68", null ],
        [ "Fixes", "a02803.html#autotoc_md69", null ],
        [ "API Changes", "a02803.html#autotoc_md70", null ]
      ] ],
      [ "Release v3.7.1 (12/15/2023)", "a02803.html#autotoc_md71", [
        [ "New Features", "a02803.html#autotoc_md72", null ],
        [ "Fixes", "a02803.html#autotoc_md73", null ],
        [ "API Changes", "a02803.html#autotoc_md74", null ]
      ] ],
      [ "Release v3.7.0 (09/08/2023)", "a02803.html#autotoc_md75", [
        [ "New Features", "a02803.html#autotoc_md76", null ],
        [ "Fixes", "a02803.html#autotoc_md77", null ],
        [ "API Changes", "a02803.html#autotoc_md78", null ]
      ] ],
      [ "Release v3.6.1 (07/14/2023)", "a02803.html#autotoc_md79", [
        [ "New Features", "a02803.html#autotoc_md80", null ],
        [ "Fixes", "a02803.html#autotoc_md81", null ]
      ] ],
      [ "Release v3.6.0 (04/04/2023)", "a02803.html#autotoc_md82", [
        [ "New Features", "a02803.html#autotoc_md83", null ],
        [ "Fixes", "a02803.html#autotoc_md84", null ],
        [ "API Changes", "a02803.html#autotoc_md85", null ]
      ] ],
      [ "Release v3.5.1 (03/26/2023)", "a02803.html#autotoc_md86", [
        [ "New Features", "a02803.html#autotoc_md87", null ]
      ] ],
      [ "Release v3.5.0 (03/14/2023)", "a02803.html#autotoc_md88", [
        [ "New Features", "a02803.html#autotoc_md89", null ]
      ] ],
      [ "Release v3.4.3 (12/23/2022)", "a02803.html#autotoc_md90", [
        [ "New Features", "a02803.html#autotoc_md91", null ],
        [ "Fixes", "a02803.html#autotoc_md92", null ]
      ] ],
      [ "Release v3.4.2 (12/04/2022)", "a02803.html#autotoc_md93", [
        [ "Fixes", "a02803.html#autotoc_md94", null ]
      ] ],
      [ "Release v3.4.1 (11/11/2022)", "a02803.html#autotoc_md95", [
        [ "Fixes", "a02803.html#autotoc_md96", null ]
      ] ],
      [ "Release v3.4.0 (10/27/2022)", "a02803.html#autotoc_md97", [
        [ "New Features", "a02803.html#autotoc_md98", null ],
        [ "Fixes", "a02803.html#autotoc_md99", null ]
      ] ],
      [ "Release v3.3.3 (10/06/2021)", "a02803.html#autotoc_md100", [
        [ "New features", "a02803.html#autotoc_md101", null ],
        [ "Fixes", "a02803.html#autotoc_md102", null ]
      ] ],
      [ "Release v3.3.2 (06/20/2021)", "a02803.html#autotoc_md103", [
        [ "New features", "a02803.html#autotoc_md104", null ],
        [ "Fixes", "a02803.html#autotoc_md105", null ]
      ] ],
      [ "Release v3.3.1 (04/23/2021)", "a02803.html#autotoc_md106", [
        [ "New features", "a02803.html#autotoc_md107", null ],
        [ "Fixes", "a02803.html#autotoc_md108", null ]
      ] ],
      [ "Release v3.3.0 (01/22/2021)", "a02803.html#autotoc_md109", [
        [ "API Updates", "a02803.html#autotoc_md110", null ],
        [ "New features", "a02803.html#autotoc_md111", null ],
        [ "Fixes", "a02803.html#autotoc_md112", null ]
      ] ],
      [ "Release v3.2.5 (11/30/2020)", "a02803.html#autotoc_md113", [
        [ "New features", "a02803.html#autotoc_md114", null ],
        [ "Fixes", "a02803.html#autotoc_md115", null ]
      ] ],
      [ "Release v3.2.4 (10/17/2020)", "a02803.html#autotoc_md116", [
        [ "New features", "a02803.html#autotoc_md117", null ],
        [ "Fixes", "a02803.html#autotoc_md118", null ]
      ] ],
      [ "Release v3.2.3 (09/12/2020)", "a02803.html#autotoc_md119", [
        [ "New features", "a02803.html#autotoc_md120", null ],
        [ "Fixes", "a02803.html#autotoc_md121", null ]
      ] ],
      [ "Release v3.2.2 (07/28/2020)", "a02803.html#autotoc_md122", [
        [ "New Features", "a02803.html#autotoc_md123", null ],
        [ "Fixes", "a02803.html#autotoc_md124", null ]
      ] ],
      [ "Release v3.2.1 (06/29/2020)", "a02803.html#autotoc_md125", [
        [ "Fixes", "a02803.html#autotoc_md126", null ]
      ] ],
      [ "Release v3.2.0 (06/10/2020)", "a02803.html#autotoc_md127", [
        [ "New features", "a02803.html#autotoc_md128", null ],
        [ "Known issues", "a02803.html#autotoc_md129", null ]
      ] ],
      [ "Release v3.1.1 (03/06/2020)", "a02803.html#autotoc_md130", null ],
      [ "Release v3.1.0 (02/05/2020)", "a02803.html#autotoc_md131", null ],
      [ "Release 11/22/2019", "a02803.html#autotoc_md132", null ],
      [ "Release 08/30/2019", "a02803.html#autotoc_md133", null ],
      [ "Release 05/17/2019", "a02803.html#autotoc_md134", null ],
      [ "Release 03/04/2019", "a02803.html#autotoc_md135", null ],
      [ "Release 01/25/2019", "a02803.html#autotoc_md136", null ],
      [ "Release 01/04/2019", "a02803.html#autotoc_md137", null ],
      [ "Release 10/25/2018", "a02803.html#autotoc_md138", null ],
      [ "Release 08/17/2018", "a02803.html#autotoc_md139", null ],
      [ "Release 07/25/2018", "a02803.html#autotoc_md140", null ],
      [ "Release 07/18/2018", "a02803.html#autotoc_md141", null ],
      [ "Release 03/29/2018", "a02803.html#autotoc_md142", null ],
      [ "Release 01/15/2018", "a02803.html#autotoc_md143", null ],
      [ "Release 11/22/2017", "a02803.html#autotoc_md144", null ],
      [ "Release 11/17/2017", "a02803.html#autotoc_md145", null ],
      [ "Release 07/01/2017", "a02803.html#autotoc_md146", null ],
      [ "Release 01/08/2016", "a02803.html#autotoc_md147", null ],
      [ "Release 9/19/2015", "a02803.html#autotoc_md148", null ]
    ] ],
    [ "Security Policy", "a02804.html", [
      [ "Supported Versions", "a02804.html#autotoc_md150", null ],
      [ "Reporting a Vulnerability", "a02804.html#autotoc_md151", null ]
    ] ],
    [ "Deprecated List", "a01400.html", null ],
    [ "Modules", "modules.html", "modules" ],
    [ "Namespaces", "namespaces.html", [
      [ "Namespace List", "namespaces.html", "namespaces_dup" ],
      [ "Namespace Members", "namespacemembers.html", [
        [ "All", "namespacemembers.html", null ],
        [ "Functions", "namespacemembers_func.html", null ]
      ] ]
    ] ],
    [ "Data Structures", "annotated.html", [
      [ "Data Structures", "annotated.html", "annotated_dup" ],
      [ "Data Structure Index", "classes.html", null ],
      [ "Class Hierarchy", "hierarchy.html", "hierarchy" ],
      [ "Data Fields", "functions.html", [
        [ "All", "functions.html", null ],
        [ "Functions", "functions_func.html", null ],
        [ "Variables", "functions_vars.html", null ]
      ] ]
    ] ],
    [ "Files", "files.html", [
      [ "File List", "files.html", "files_dup" ],
      [ "Globals", "globals.html", [
        [ "All", "globals.html", "globals_dup" ],
        [ "Functions", "globals_func.html", "globals_func" ],
        [ "Variables", "globals_vars.html", null ],
        [ "Typedefs", "globals_type.html", null ],
        [ "Enumerations", "globals_enum.html", null ],
        [ "Enumerator", "globals_eval.html", null ],
        [ "Macros", "globals_defs.html", "globals_defs" ]
      ] ]
    ] ]
  ] ]
];

var NAVTREEINDEX =
[
"a00005.html",
"a00356.html#a08e8a80be2717ece7c5ed5cc0a27fbab",
"a00356.html#aa0117f3d3f9a9ae65a3fab1e68b7caef",
"a00497.html#a6d2fa2e22a151bea100d7c7ee84dbe7f",
"a01403.html#ga098c4c2c724b90b7e2f4ecf12b9530b7",
"a01407.html#ga7bd1ad830360fc8b988f855da6d0d5ba",
"a01414.html",
"a01422.html#a88737f422c86c2246a698fd64d59db1a",
"a01732.html#af8c982fdcb8edc1ff6b1e838fab281ac",
"a02376.html",
"globals_defs_m.html"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';