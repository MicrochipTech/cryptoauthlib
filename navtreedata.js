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
    [ "License", "a02897.html", null ],
    [ "IP Protection with Symmetric Authentication", "a02898.html", [
      [ "User Considerations", "a02898.html#autotoc_md0", null ],
      [ "Examples", "a02898.html#autotoc_md1", null ]
    ] ],
    [ "PKCS11 Application Information", "a02899.html", [
      [ "Setting up cryptoauthlib as a PKCS11 Provider for your system (LINUX)", "a02899.html#autotoc_md2", [
        [ "Update libp11 on the system. The version should be at minimum 0.4.10", "a02899.html#autotoc_md3", null ],
        [ "Build and Install cryptoauthlib with PKCS11 support", "a02899.html#autotoc_md4", null ],
        [ "Configuring the cryptoauthlib PKCS11 library", "a02899.html#autotoc_md5", [
          [ "cryptoauthlib.conf", "a02899.html#autotoc_md6", null ],
          [ "slot.conf.tmpl", "a02899.html#autotoc_md7", [
            [ "interface", "a02899.html#autotoc_md8", null ],
            [ "freeslots", "a02899.html#autotoc_md9", null ]
          ] ]
        ] ],
        [ "Using p11-kit-proxy", "a02899.html#autotoc_md10", null ],
        [ "Without using p11-kit-proxy", "a02899.html#autotoc_md11", null ],
        [ "Testing", "a02899.html#autotoc_md12", null ]
      ] ]
    ] ],
    [ "Application Support", "a02900.html", null ],
    [ "Secure boot using ATECC608", "a02901.html", [
      [ "Implementation Considerations", "a02901.html#autotoc_md13", null ],
      [ "Examples", "a02901.html#autotoc_md14", null ]
    ] ],
    [ "Contribution Guidelines", "a02903.html", null ],
    [ "Migrating to v3.7.6 to v3.7.7", "a02904.html", [
      [ "atcacert", "a02904.html#autotoc_md17", [
        [ "atcacert API Migration", "a02904.html#autotoc_md18", null ]
      ] ],
      [ "Cryptoauthlib HAL Architecture", "a01506.html#autotoc_md21", null ],
      [ "CryptoAuthLib Supported HAL Layers", "a01506.html#autotoc_md23", [
        [ "Microchip Harmony 3 for all PIC32 & ARM products - Use the Harmony 3 Configurator to generate and configure prjects", "a01506.html#autotoc_md24", null ],
        [ "Microchip 8 & 16 bit products - AVR, PIC16/18, PIC24/DSPIC", "a01506.html#autotoc_md25", null ],
        [ "OS & RTOS integrations", "a01506.html#autotoc_md26", null ],
        [ "Legacy Support - <a href=\"https://www.microchip.com/start\" >Atmel START</a> for AVR, ARM based processesors (SAM)", "a01506.html#autotoc_md27", null ],
        [ "Legacy Support - ASF3 for ARM Cortex-m0 & Cortex-m based processors (SAM)", "a01506.html#autotoc_md28", null ]
      ] ]
    ] ],
    [ "openssl directory - Purpose", "a02909.html", null ],
    [ "atcab", "a02910.html", [
      [ "atcab API reference", "a02910.html#autotoc_md29", null ]
    ] ],
    [ "Python CryptoAuthLib module", "a02911.html", [
      [ "Introduction", "a02911.html#autotoc_md31", [
        [ "Code Examples", "a02911.html#autotoc_md32", null ]
      ] ],
      [ "Installation", "a02911.html#autotoc_md33", [
        [ "CryptoAuthLib python module can be installed through Python's pip tool:", "a02911.html#autotoc_md34", null ],
        [ "To upgrade your installation when new releases are made:", "a02911.html#autotoc_md35", null ],
        [ "If you ever need to remove your installation:", "a02911.html#autotoc_md36", null ]
      ] ],
      [ "What does python CryptoAuthLib package do?", "a02911.html#autotoc_md37", null ],
      [ "Supported hardware", "a02911.html#autotoc_md38", null ],
      [ "Supported devices", "a02911.html#autotoc_md39", null ],
      [ "Using cryptoauthlib python module", "a02911.html#autotoc_md40", null ],
      [ "In Summary", "a02911.html#autotoc_md41", [
        [ "Step I: Import the module", "a02911.html#autotoc_md42", null ],
        [ "Step II: Initilize the module", "a02911.html#autotoc_md43", null ],
        [ "Step III: Use Cryptoauthlib APIs", "a02911.html#autotoc_md44", null ]
      ] ],
      [ "Code portability", "a02911.html#autotoc_md45", null ],
      [ "Cryptoauthlib module API documentation", "a02911.html#autotoc_md46", [
        [ "help() command", "a02911.html#autotoc_md47", null ],
        [ "dir() command", "a02911.html#autotoc_md48", null ]
      ] ],
      [ "Code Examples", "a02911.html#autotoc_md49", null ],
      [ "Tests", "a02911.html#autotoc_md50", null ],
      [ "Release notes", "a02911.html#autotoc_md51", null ]
    ] ],
    [ "Python CryptoAuthLib Module Testing", "a02912.html", [
      [ "Introduction", "a02912.html#autotoc_md53", [
        [ "Running", "a02912.html#autotoc_md54", null ],
        [ "Test options", "a02912.html#autotoc_md55", null ]
      ] ]
    ] ],
    [ "Microchip Cryptoauthlib Release Notes", "a02913.html", [
      [ "Release v3.7.7 (02/07/2025)", "a02913.html#autotoc_md67", [
        [ "New Features", "a02913.html#autotoc_md68", null ],
        [ "Fixes", "a02913.html#autotoc_md69", null ],
        [ "API CHANGES", "a02913.html#autotoc_md70", null ]
      ] ],
      [ "Release v3.7.6 (09/26/2024)", "a02913.html#autotoc_md71", [
        [ "New Features", "a02913.html#autotoc_md72", null ],
        [ "Fixes", "a02913.html#autotoc_md73", null ]
      ] ],
      [ "Release v3.7.5 (06/26/2024)", "a02913.html#autotoc_md74", [
        [ "New Features", "a02913.html#autotoc_md75", null ],
        [ "Fixes", "a02913.html#autotoc_md76", null ],
        [ "API Changes", "a02913.html#autotoc_md77", null ]
      ] ],
      [ "Release v3.7.4 (03/08/2024)", "a02913.html#autotoc_md78", [
        [ "New Features", "a02913.html#autotoc_md79", null ],
        [ "Fixes", "a02913.html#autotoc_md80", null ]
      ] ],
      [ "Release v3.7.3 (01/31/2024)", "a02913.html#autotoc_md81", [
        [ "New Features", "a02913.html#autotoc_md82", null ],
        [ "Fixes", "a02913.html#autotoc_md83", null ]
      ] ],
      [ "Release v3.7.2 (01/19/2024)", "a02913.html#autotoc_md84", [
        [ "New Features", "a02913.html#autotoc_md85", null ],
        [ "Fixes", "a02913.html#autotoc_md86", null ],
        [ "API Changes", "a02913.html#autotoc_md87", null ]
      ] ],
      [ "Release v3.7.1 (12/15/2023)", "a02913.html#autotoc_md88", [
        [ "New Features", "a02913.html#autotoc_md89", null ],
        [ "Fixes", "a02913.html#autotoc_md90", null ],
        [ "API Changes", "a02913.html#autotoc_md91", null ]
      ] ],
      [ "Release v3.7.0 (09/08/2023)", "a02913.html#autotoc_md92", [
        [ "New Features", "a02913.html#autotoc_md93", null ],
        [ "Fixes", "a02913.html#autotoc_md94", null ],
        [ "API Changes", "a02913.html#autotoc_md95", null ]
      ] ],
      [ "Release v3.6.1 (07/14/2023)", "a02913.html#autotoc_md96", [
        [ "New Features", "a02913.html#autotoc_md97", null ],
        [ "Fixes", "a02913.html#autotoc_md98", null ]
      ] ],
      [ "Release v3.6.0 (04/04/2023)", "a02913.html#autotoc_md99", [
        [ "New Features", "a02913.html#autotoc_md100", null ],
        [ "Fixes", "a02913.html#autotoc_md101", null ],
        [ "API Changes", "a02913.html#autotoc_md102", null ]
      ] ],
      [ "Release v3.5.1 (03/26/2023)", "a02913.html#autotoc_md103", [
        [ "New Features", "a02913.html#autotoc_md104", null ]
      ] ],
      [ "Release v3.5.0 (03/14/2023)", "a02913.html#autotoc_md105", [
        [ "New Features", "a02913.html#autotoc_md106", null ]
      ] ],
      [ "Release v3.4.3 (12/23/2022)", "a02913.html#autotoc_md107", [
        [ "New Features", "a02913.html#autotoc_md108", null ],
        [ "Fixes", "a02913.html#autotoc_md109", null ]
      ] ],
      [ "Release v3.4.2 (12/04/2022)", "a02913.html#autotoc_md110", [
        [ "Fixes", "a02913.html#autotoc_md111", null ]
      ] ],
      [ "Release v3.4.1 (11/11/2022)", "a02913.html#autotoc_md112", [
        [ "Fixes", "a02913.html#autotoc_md113", null ]
      ] ],
      [ "Release v3.4.0 (10/27/2022)", "a02913.html#autotoc_md114", [
        [ "New Features", "a02913.html#autotoc_md115", null ],
        [ "Fixes", "a02913.html#autotoc_md116", null ]
      ] ],
      [ "Release v3.3.3 (10/06/2021)", "a02913.html#autotoc_md117", [
        [ "New features", "a02913.html#autotoc_md118", null ],
        [ "Fixes", "a02913.html#autotoc_md119", null ]
      ] ],
      [ "Release v3.3.2 (06/20/2021)", "a02913.html#autotoc_md120", [
        [ "New features", "a02913.html#autotoc_md121", null ],
        [ "Fixes", "a02913.html#autotoc_md122", null ]
      ] ],
      [ "Release v3.3.1 (04/23/2021)", "a02913.html#autotoc_md123", [
        [ "New features", "a02913.html#autotoc_md124", null ],
        [ "Fixes", "a02913.html#autotoc_md125", null ]
      ] ],
      [ "Release v3.3.0 (01/22/2021)", "a02913.html#autotoc_md126", [
        [ "API Updates", "a02913.html#autotoc_md127", null ],
        [ "New features", "a02913.html#autotoc_md128", null ],
        [ "Fixes", "a02913.html#autotoc_md129", null ]
      ] ],
      [ "Release v3.2.5 (11/30/2020)", "a02913.html#autotoc_md130", [
        [ "New features", "a02913.html#autotoc_md131", null ],
        [ "Fixes", "a02913.html#autotoc_md132", null ]
      ] ],
      [ "Release v3.2.4 (10/17/2020)", "a02913.html#autotoc_md133", [
        [ "New features", "a02913.html#autotoc_md134", null ],
        [ "Fixes", "a02913.html#autotoc_md135", null ]
      ] ],
      [ "Release v3.2.3 (09/12/2020)", "a02913.html#autotoc_md136", [
        [ "New features", "a02913.html#autotoc_md137", null ],
        [ "Fixes", "a02913.html#autotoc_md138", null ]
      ] ],
      [ "Release v3.2.2 (07/28/2020)", "a02913.html#autotoc_md139", [
        [ "New Features", "a02913.html#autotoc_md140", null ],
        [ "Fixes", "a02913.html#autotoc_md141", null ]
      ] ],
      [ "Release v3.2.1 (06/29/2020)", "a02913.html#autotoc_md142", [
        [ "Fixes", "a02913.html#autotoc_md143", null ]
      ] ],
      [ "Release v3.2.0 (06/10/2020)", "a02913.html#autotoc_md144", [
        [ "New features", "a02913.html#autotoc_md145", null ],
        [ "Known issues", "a02913.html#autotoc_md146", null ]
      ] ],
      [ "Release v3.1.1 (03/06/2020)", "a02913.html#autotoc_md147", null ],
      [ "Release v3.1.0 (02/05/2020)", "a02913.html#autotoc_md148", null ],
      [ "Release 11/22/2019", "a02913.html#autotoc_md149", null ],
      [ "Release 08/30/2019", "a02913.html#autotoc_md150", null ],
      [ "Release 05/17/2019", "a02913.html#autotoc_md151", null ],
      [ "Release 03/04/2019", "a02913.html#autotoc_md152", null ],
      [ "Release 01/25/2019", "a02913.html#autotoc_md153", null ],
      [ "Release 01/04/2019", "a02913.html#autotoc_md154", null ],
      [ "Release 10/25/2018", "a02913.html#autotoc_md155", null ],
      [ "Release 08/17/2018", "a02913.html#autotoc_md156", null ],
      [ "Release 07/25/2018", "a02913.html#autotoc_md157", null ],
      [ "Release 07/18/2018", "a02913.html#autotoc_md158", null ],
      [ "Release 03/29/2018", "a02913.html#autotoc_md159", null ],
      [ "Release 01/15/2018", "a02913.html#autotoc_md160", null ],
      [ "Release 11/22/2017", "a02913.html#autotoc_md161", null ],
      [ "Release 11/17/2017", "a02913.html#autotoc_md162", null ],
      [ "Release 07/01/2017", "a02913.html#autotoc_md163", null ],
      [ "Release 01/08/2016", "a02913.html#autotoc_md164", null ],
      [ "Release 9/19/2015", "a02913.html#autotoc_md165", null ]
    ] ],
    [ "Security Policy", "a02914.html", [
      [ "Supported Versions", "a02914.html#autotoc_md167", null ],
      [ "Reporting a Vulnerability", "a02914.html#autotoc_md168", null ]
    ] ],
    [ "Deprecated List", "a01496.html", null ],
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
"a00383.html#a071a95b4b2048e0d879e6e13984e38fd",
"a00383.html#a9cc740e22e15f08a8b90873a2b3b47e8",
"a00533.html",
"a01498.html#ga28c369c92f1a7c2f61512cde463b8ff5",
"a01503.html#ga5d7eff7a29bc02cfe16bc3d25e3ef2eb",
"a01509.html#gaa35682dc98e33ce3d6fad1fc902cdff0",
"a01513.html#a82bd7bbea46866cb644016ea7faff329",
"a01816.html#afa39cec9e8d332618910a0f519b5b48d",
"a02444.html",
"dir_39966be8f8e069f6fa92c98611834f6b.html"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';