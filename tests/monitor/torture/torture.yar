// SPDX-License-Identifier: MIT
// Rules for the Antinomie stress samples. Add this file as a custom YARA
// group in Tools > Rule manager; turn on memory and recovered-file scanning
// to see all four targets.
rule Antinomie_Torture_Executable
{
    meta:
        description = "Marker compiled into ant-detect-yara and ant-torture"
        author = "Antinomie"
        license = "MIT"
        severity = "low"
    strings:
        $marker = "ANTINOMIE_TORTURE_YARA_EXECUTABLE_MARKER"
    condition:
        $marker
}

rule Antinomie_Torture_Dropped_File
{
    meta:
        description = "Marker written only to /tmp/antinomie-torture-yara-dropped.bin"
        author = "Antinomie"
        license = "MIT"
        severity = "medium"
    strings:
        $marker = "ANTINOMIE_TORTURE_YARA_DROPPED_MARKER"
    condition:
        $marker
}

rule Antinomie_Torture_Memory_Only
{
    meta:
        description = "Marker assembled at run time; only memory and core dumps hold it"
        author = "Antinomie"
        license = "MIT"
        severity = "high"
    strings:
        $marker = "ANTINOMIE_TORTURE_YARA_MEMORY_MARKER"
    condition:
        $marker
}

rule Antinomie_Torture_Core_Pattern
{
    meta:
        description = "Heap pages of ant-crash-core; many hits mean a complete core"
        author = "Antinomie"
        license = "MIT"
        severity = "low"
    strings:
        $page = "ANTINOMIE-CORE-PATTERN page"
    condition:
        #page > 100
}
