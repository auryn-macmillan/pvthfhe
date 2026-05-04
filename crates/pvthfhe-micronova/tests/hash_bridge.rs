//! RED tests for the simplified Poseidon↔Keccak bridge.

use pvthfhe_micronova::hash_bridge::poseidon_keccak_bridge;

fn encode_fixed(index: u8) -> [u8; 32] {
    [index; 32]
}

fn expected_keccak(index: u8) -> [u8; 32] {
    match index {
        0 => [
            41, 13, 236, 217, 84, 139, 98, 168, 214, 3, 69, 169, 136, 56, 111, 200, 75, 166, 188,
            149, 72, 64, 8, 246, 54, 47, 147, 22, 14, 243, 229, 99,
        ],
        1 => [
            206, 188, 136, 130, 254, 203, 236, 127, 184, 13, 44, 244, 179, 18, 190, 192, 24, 136,
            76, 45, 102, 102, 124, 103, 169, 5, 8, 33, 75, 216, 186, 252,
        ],
        2 => [
            238, 74, 7, 159, 91, 20, 162, 68, 101, 24, 29, 69, 175, 50, 168, 5, 60, 45, 68, 100,
            70, 215, 1, 147, 89, 226, 16, 184, 46, 83, 184, 186,
        ],
        3 => [
            74, 122, 77, 227, 125, 239, 142, 16, 134, 18, 97, 245, 142, 16, 3, 230, 8, 109, 244,
            73, 182, 21, 187, 65, 28, 57, 102, 149, 72, 225, 157, 186,
        ],
        4 => [
            184, 191, 30, 51, 211, 93, 34, 142, 139, 248, 250, 189, 213, 164, 249, 1, 64, 56, 130,
            157, 217, 13, 191, 89, 18, 124, 160, 149, 173, 101, 199, 204,
        ],
        5 => [
            216, 84, 29, 153, 93, 133, 203, 100, 213, 28, 99, 72, 226, 30, 236, 214, 229, 28, 188,
            218, 91, 12, 82, 7, 174, 135, 230, 5, 131, 158, 112, 239,
        ],
        6 => [
            197, 80, 129, 97, 151, 68, 87, 189, 74, 122, 152, 84, 122, 14, 224, 93, 114, 17, 5,
            174, 250, 99, 163, 182, 214, 248, 29, 196, 11, 102, 146, 155,
        ],
        7 => [
            123, 6, 32, 100, 9, 90, 151, 87, 138, 15, 12, 245, 53, 221, 50, 31, 72, 241, 2, 235,
            200, 122, 140, 161, 109, 212, 180, 197, 252, 108, 77, 168,
        ],
        8 => [
            154, 124, 12, 96, 124, 141, 61, 53, 140, 169, 231, 19, 91, 146, 94, 168, 186, 194, 171,
            185, 253, 209, 151, 61, 200, 242, 237, 100, 9, 191, 125, 217,
        ],
        9 => [
            11, 45, 69, 170, 95, 106, 68, 78, 68, 200, 8, 8, 45, 106, 200, 43, 221, 60, 221, 125,
            187, 132, 144, 222, 169, 214, 248, 81, 183, 228, 214, 116,
        ],
        _ => unreachable!("test covers only indices 0..10"),
    }
}

fn assert_golden_vector(index: u8) {
    let input = encode_fixed(index);

    assert_eq!(poseidon_keccak_bridge(&input), expected_keccak(index));
}

macro_rules! golden_vector_test {
    ($name:ident, $index:expr) => {
        #[test]
        fn $name() {
            assert_golden_vector($index);
        }
    };
}

golden_vector_test!(hash_bridge_golden_vector_0, 0);
golden_vector_test!(hash_bridge_golden_vector_1, 1);
golden_vector_test!(hash_bridge_golden_vector_2, 2);
golden_vector_test!(hash_bridge_golden_vector_3, 3);
golden_vector_test!(hash_bridge_golden_vector_4, 4);
golden_vector_test!(hash_bridge_golden_vector_5, 5);
golden_vector_test!(hash_bridge_golden_vector_6, 6);
golden_vector_test!(hash_bridge_golden_vector_7, 7);
golden_vector_test!(hash_bridge_golden_vector_8, 8);
golden_vector_test!(hash_bridge_golden_vector_9, 9);
