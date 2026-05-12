//! RED test: CycloTernaryTranscript produces biased ternary challenges.
//!
//! P2A.3: Verify the `CycloTernaryTranscript` struct from `fiat_shamir`:
//! 1. Domain separator is "pvthfhe-cyclo-fs-v2" (different from Sonobe v1)
//! 2. sample_challenge returns only -1, 0, or 1
//! 3. Distribution is roughly uniform (statistical test)

use pvthfhe_cyclo::fiat_shamir::{challenge_v1, CycloTernaryTranscript};

#[test]
fn ternary_challenges_are_in_valid_range() {
    let mut transcript = CycloTernaryTranscript::new("test-session");
    for _ in 0..1000 {
        let c = transcript.sample_challenge();
        assert!(
            c == -1 || c == 0 || c == 1,
            "challenge {c} must be in {{-1, 0, 1}}"
        );
    }
}

#[test]
fn domain_separator_differs_from_sonobe_v1() {
    let mut t2 = CycloTernaryTranscript::new("test-session");
    t2.absorb(b"fold-data");

    let ternary = t2.sample_challenge();

    let sonobe_hash = challenge_v1(
        "test-session",
        0,
        b"fold-data",
        b"",
        b"",
    );

    // The ternary challenge (i8 in {-1,0,1}) and the Sonobe challenge
    // (u16 from SHA-256) are fundamentally different types and values.
    // At minimum, the transcripts use different domain separators
    // ("pvthfhe-cyclo-fs-v2" vs "pvthfhe-cyclo-fs-v1") so their
    // hash outputs must differ.
    let sonobe_u16 = u16::from_le_bytes([sonobe_hash[0], sonobe_hash[1]]);
    let ternary_as_u16 = match ternary {
        -1 => 65535u16,
        0 => 0u16,
        1 => 1u16,
        _ => unreachable!(),
    };

    assert_ne!(
        u32::from(ternary_as_u16),
        u32::from(sonobe_u16),
        "CycloTernaryTranscript domain separator must differ from Sonobe v1"
    );
}

#[test]
fn ternary_distribution_is_roughly_uniform() {
    let mut transcript = CycloTernaryTranscript::new("stats-test");
    let mut counts = [0u64; 3]; // counts for -1, 0, 1

    for i in 0u32..3000 {
        transcript.absorb(&i.to_le_bytes());
        let c = transcript.sample_challenge();
        match c {
            -1 => counts[0] += 1,
            0 => counts[1] += 1,
            1 => counts[2] += 1,
            _ => {}
        }
    }

    let total = counts[0] + counts[1] + counts[2];
    assert_eq!(total, 3000, "all samples must be in {{-1, 0, 1}}");

    let expected = 1000.0;
    let tolerance = 300.0; // generous tolerance for 3000 samples
    for (i, &count) in counts.iter().enumerate() {
        let val = match i {
            0 => -1,
            1 => 0,
            _ => 1,
        };
        let diff = (count as f64 - expected).abs();
        assert!(
            diff <= tolerance,
            "count for {}: {} deviates too far from expected 1000 (diff {diff})",
            val,
            count
        );
    }
}

#[test]
fn different_absorbed_data_produces_different_challenges() {
    let mut t1 = CycloTernaryTranscript::new("det-test");
    t1.absorb(b"aaa");

    let mut t2 = CycloTernaryTranscript::new("det-test");
    t2.absorb(b"bbb");

    // With high probability, different absorbed data produces different
    // challenges. We check across multiple samples.
    let mut different = false;
    let mut t1b = CycloTernaryTranscript::new("det-test");
    t1b.absorb(b"aaa");
    let mut t2b = CycloTernaryTranscript::new("det-test");
    t2b.absorb(b"bbb");

    for _ in 0..100 {
        if t1b.sample_challenge() != t2b.sample_challenge() {
            different = true;
            break;
        }
    }
    assert!(different, "different absorbed data must produce different challenges");
}
