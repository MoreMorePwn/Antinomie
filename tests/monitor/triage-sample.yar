// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
rule Antinomie_Triage_Sample {
    meta:
        description = "Benign synthetic triage sample marker; not a malware verdict"
        author = "MikiMiku (MoreMorePwn)"
        license = "MIT"
    strings:
        $marker = "ANTINOMIE_TRIAGE_FIXTURE_v1"
    condition:
        $marker
}
