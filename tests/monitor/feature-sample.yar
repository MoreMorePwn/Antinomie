// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
rule Antinomie_Feature_Sample {
    meta:
        description = "Benign Antinomie feature sample; not a malware verdict"
        author = "MikiMiku (MoreMorePwn)"
        license = "MIT"
    strings:
        $marker = "ANTINOMIE_FEATURE_SAMPLE_v1"
        $agent = "AntinomieFeatureSample/1.0"
        $install = "/tmp/antinomie-feature-sample"
    condition:
        uint32(0) == 0x464c457f and 2 of them
}
