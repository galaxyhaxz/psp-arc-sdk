# psp-arc-sdk
Tools for building/extracting PSP (PlayStation Portable) arc sdk updates

These tools will allow you to extract as well as create the `.arc` format updates found within the early PSP sdks. These arcs are a simple format encrypted with DES-CBC. This tool has been tested with 0.6.5, 1.0.2, 1.0.3, and 1.5.0 sdk version arc files.

I got lazy and made separate tools for each, but they should eventually be merged into one tool.

[build](build) builds a `.arc` update from the specified list file. The list file contains the files to be included in the archive.

[extract](extract) extracts a `.arc` update into a folder and writes a list file. Can be rebuilt into an identical update.

Key and IV are specified via command line.

Credits to Mathieulh for discovering the encryption method.
