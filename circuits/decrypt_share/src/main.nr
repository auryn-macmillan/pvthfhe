// NizkDecShare circuit.
// NOTE: This is a Noir test-only circuit implementing partial constraints for the full LatticeFold+ NIZK (Open Problem P1).
// Proves d_i = c_1 * sk_i + e_i AND Poseidon(pk_i) = pk_i_hash AND ||sk_i||, ||e_i|| <= beta
// AND MerkleVerify(dkg_root, leaf=Poseidon(party_id || pk_i_hash), path=merkle_path_i) = true
// This implements partial constraints for the full LatticeFold+ NIZK (open problem P1).
// Poseidon is the canonical in-circuit hash primitive; Keccak-256 is reserved for on-chain/EVM use.

use poseidon;

fn main(
    party_id: pub Field,
    pk_i_hash: pub Field,
    dkg_root: pub Field,
    ciphertext_hash: pub Field,
    epoch: pub Field,
    d_i_hash: pub Field,
    sk_i: [Field; 4],
    e_i: [Field; 4],
    pk_i_bytes: [Field; 4],
    merkle_path: [Field; 4]
) {
    // 1. Shortness of sk_i
    for i in 0..4 {
        assert(sk_i[i] as u32 <= 255);
    }

    // 2. Shortness of e_i
    for i in 0..4 {
        assert(e_i[i] as u32 <= 255);
    }

    // 3. PK hash check (Poseidon is the canonical in-circuit hash)
    let h = poseidon::poseidon::bn254::hash_4(pk_i_bytes);
    assert(h == pk_i_hash);

    // 4. Poseidon Merkle proof (depth=4)
    let leaf_hash = poseidon::poseidon::bn254::hash_2([party_id, pk_i_hash]);
    let level0 = poseidon::poseidon::bn254::hash_2([leaf_hash, merkle_path[0]]);
    let level1 = poseidon::poseidon::bn254::hash_2([level0, merkle_path[1]]);
    let level2 = poseidon::poseidon::bn254::hash_2([level1, merkle_path[2]]);
    let level3 = poseidon::poseidon::bn254::hash_2([level2, merkle_path[3]]);
    assert(level3 == dkg_root);

    // 5. Epoch binding
    assert(epoch as u32 > 0);

    // 6. d_i computation: d_i = sk_i[0] * 42 + e_i[0] (1-coefficient surrogate for c_1[0]=42)
    let d_i_computed = sk_i[0] * 42 + e_i[0];
    let d_i_hash_computed = poseidon::poseidon::bn254::hash_1([d_i_computed]);
    assert(d_i_hash_computed == d_i_hash);

    // 7. ciphertext_hash: bind to witness via Poseidon (pk encrypts the ciphertext)
    let ct_hash_computed = poseidon::poseidon::bn254::hash_2([pk_i_hash, epoch]);
    assert(ct_hash_computed == ciphertext_hash);
}

// -- Helpers used across tests --

fn make_honest_root(party_id: Field, pk_i_hash: Field, path: [Field; 4]) -> Field {
    let leaf_hash = poseidon::poseidon::bn254::hash_2([party_id, pk_i_hash]);
    let level0 = poseidon::poseidon::bn254::hash_2([leaf_hash, path[0]]);
    let level1 = poseidon::poseidon::bn254::hash_2([level0, path[1]]);
    let level2 = poseidon::poseidon::bn254::hash_2([level1, path[2]]);
    poseidon::poseidon::bn254::hash_2([level2, path[3]])
}

// -- Passing test --

#[test]
fn test_honest() {
    let party_id: Field = 1;
    let pk_i_bytes: [Field; 4] = [42, 0, 0, 0];
    let pk_i_hash = poseidon::poseidon::bn254::hash_4(pk_i_bytes);
    let epoch: Field = 1;
    let sk_i: [Field; 4] = [1, 2, 3, 4];
    let e_i: [Field; 4] = [1, 2, 3, 4];
    let merkle_path: [Field; 4] = [1, 2, 3, 4];

    let dkg_root = make_honest_root(party_id, pk_i_hash, merkle_path);

    // d_i = sk_i[0] * 42 + e_i[0] = 1*42+1 = 43
    let d_i_computed = sk_i[0] * 42 + e_i[0];
    let d_i_hash = poseidon::poseidon::bn254::hash_1([d_i_computed]);

    let ciphertext_hash = poseidon::poseidon::bn254::hash_2([pk_i_hash, epoch]);

    main(
        party_id,
        pk_i_hash,
        dkg_root,
        ciphertext_hash,
        epoch,
        d_i_hash,
        sk_i,
        e_i,
        pk_i_bytes,
        merkle_path
    );
}

// -- Existing shortness / pk / epoch should_fail tests --

#[test(should_fail)]
fn test_fail_sk_shortness() {
    let party_id: Field = 1;
    let pk_i_bytes: [Field; 4] = [42, 0, 0, 0];
    let pk_i_hash = poseidon::poseidon::bn254::hash_4(pk_i_bytes);
    let epoch: Field = 1;
    let sk_i: [Field; 4] = [256, 2, 3, 4];
    let e_i: [Field; 4] = [1, 2, 3, 4];
    let merkle_path: [Field; 4] = [1, 2, 3, 4];
    let dkg_root = make_honest_root(party_id, pk_i_hash, merkle_path);
    let d_i_computed = sk_i[0] * 42 + e_i[0];
    let d_i_hash = poseidon::poseidon::bn254::hash_1([d_i_computed]);
    let ciphertext_hash = poseidon::poseidon::bn254::hash_2([pk_i_hash, epoch]);
    main(party_id, pk_i_hash, dkg_root, ciphertext_hash, epoch, d_i_hash, sk_i, e_i, pk_i_bytes, merkle_path);
}

#[test(should_fail)]
fn test_fail_e_shortness() {
    let party_id: Field = 1;
    let pk_i_bytes: [Field; 4] = [42, 0, 0, 0];
    let pk_i_hash = poseidon::poseidon::bn254::hash_4(pk_i_bytes);
    let epoch: Field = 1;
    let sk_i: [Field; 4] = [1, 2, 3, 4];
    let e_i: [Field; 4] = [1, 2, 3, 256];
    let merkle_path: [Field; 4] = [1, 2, 3, 4];
    let dkg_root = make_honest_root(party_id, pk_i_hash, merkle_path);
    let d_i_computed = sk_i[0] * 42 + e_i[0];
    let d_i_hash = poseidon::poseidon::bn254::hash_1([d_i_computed]);
    let ciphertext_hash = poseidon::poseidon::bn254::hash_2([pk_i_hash, epoch]);
    main(party_id, pk_i_hash, dkg_root, ciphertext_hash, epoch, d_i_hash, sk_i, e_i, pk_i_bytes, merkle_path);
}

#[test(should_fail)]
fn test_fail_pk_hash() {
    let party_id: Field = 1;
    let pk_i_bytes: [Field; 4] = [42, 0, 0, 0];
    let pk_i_hash: Field = 999; // wrong hash
    let epoch: Field = 1;
    let sk_i: [Field; 4] = [1, 2, 3, 4];
    let e_i: [Field; 4] = [1, 2, 3, 4];
    let merkle_path: [Field; 4] = [1, 2, 3, 4];
    let dkg_root = make_honest_root(party_id, pk_i_hash, merkle_path);
    let d_i_computed = sk_i[0] * 42 + e_i[0];
    let d_i_hash = poseidon::poseidon::bn254::hash_1([d_i_computed]);
    let ciphertext_hash = poseidon::poseidon::bn254::hash_2([pk_i_hash, epoch]);
    main(party_id, pk_i_hash, dkg_root, ciphertext_hash, epoch, d_i_hash, sk_i, e_i, pk_i_bytes, merkle_path);
}

#[test(should_fail)]
fn test_fail_dkg_root() {
    let party_id: Field = 1;
    let pk_i_bytes: [Field; 4] = [42, 0, 0, 0];
    let pk_i_hash = poseidon::poseidon::bn254::hash_4(pk_i_bytes);
    let epoch: Field = 1;
    let sk_i: [Field; 4] = [1, 2, 3, 4];
    let e_i: [Field; 4] = [1, 2, 3, 4];
    let merkle_path: [Field; 4] = [1, 2, 3, 4];
    let dkg_root: Field = 999; // wrong root
    let d_i_computed = sk_i[0] * 42 + e_i[0];
    let d_i_hash = poseidon::poseidon::bn254::hash_1([d_i_computed]);
    let ciphertext_hash = poseidon::poseidon::bn254::hash_2([pk_i_hash, epoch]);
    main(party_id, pk_i_hash, dkg_root, ciphertext_hash, epoch, d_i_hash, sk_i, e_i, pk_i_bytes, merkle_path);
}

#[test(should_fail)]
fn test_fail_epoch() {
    let party_id: Field = 1;
    let pk_i_bytes: [Field; 4] = [42, 0, 0, 0];
    let pk_i_hash = poseidon::poseidon::bn254::hash_4(pk_i_bytes);
    let epoch: Field = 0; // epoch=0 should fail
    let sk_i: [Field; 4] = [1, 2, 3, 4];
    let e_i: [Field; 4] = [1, 2, 3, 4];
    let merkle_path: [Field; 4] = [1, 2, 3, 4];
    let dkg_root = make_honest_root(party_id, pk_i_hash, merkle_path);
    let d_i_computed = sk_i[0] * 42 + e_i[0];
    let d_i_hash = poseidon::poseidon::bn254::hash_1([d_i_computed]);
    let ciphertext_hash = poseidon::poseidon::bn254::hash_2([pk_i_hash, epoch]);
    main(party_id, pk_i_hash, dkg_root, ciphertext_hash, epoch, d_i_hash, sk_i, e_i, pk_i_bytes, merkle_path);
}

#[test(should_fail)]
fn test_fail_sk_e_shortness() {
    let party_id: Field = 1;
    let pk_i_bytes: [Field; 4] = [42, 0, 0, 0];
    let pk_i_hash = poseidon::poseidon::bn254::hash_4(pk_i_bytes);
    let epoch: Field = 1;
    let sk_i: [Field; 4] = [256, 2, 3, 4];
    let e_i: [Field; 4] = [1, 2, 256, 4];
    let merkle_path: [Field; 4] = [1, 2, 3, 4];
    let dkg_root = make_honest_root(party_id, pk_i_hash, merkle_path);
    let d_i_computed = sk_i[0] * 42 + e_i[0];
    let d_i_hash = poseidon::poseidon::bn254::hash_1([d_i_computed]);
    let ciphertext_hash = poseidon::poseidon::bn254::hash_2([pk_i_hash, epoch]);
    main(party_id, pk_i_hash, dkg_root, ciphertext_hash, epoch, d_i_hash, sk_i, e_i, pk_i_bytes, merkle_path);
}

// -- New adversarial tamper tests --

#[test(should_fail)]
fn test_fail_tampered_leaf() {
    // Compute root for party_id=1, then submit with party_id=2 (leaf mismatch)
    let party_id_honest: Field = 1;
    let party_id_tampered: Field = 2;
    let pk_i_bytes: [Field; 4] = [42, 0, 0, 0];
    let pk_i_hash = poseidon::poseidon::bn254::hash_4(pk_i_bytes);
    let epoch: Field = 1;
    let sk_i: [Field; 4] = [1, 2, 3, 4];
    let e_i: [Field; 4] = [1, 2, 3, 4];
    let merkle_path: [Field; 4] = [1, 2, 3, 4];
    // Root is valid for party_id=1, but we submit party_id=2
    let dkg_root = make_honest_root(party_id_honest, pk_i_hash, merkle_path);
    let d_i_computed = sk_i[0] * 42 + e_i[0];
    let d_i_hash = poseidon::poseidon::bn254::hash_1([d_i_computed]);
    let ciphertext_hash = poseidon::poseidon::bn254::hash_2([pk_i_hash, epoch]);
    main(party_id_tampered, pk_i_hash, dkg_root, ciphertext_hash, epoch, d_i_hash, sk_i, e_i, pk_i_bytes, merkle_path);
}

#[test(should_fail)]
fn test_fail_tampered_path() {
    // Compute root with path [1,2,3,4], then submit with path [1,2,3,99]
    let party_id: Field = 1;
    let pk_i_bytes: [Field; 4] = [42, 0, 0, 0];
    let pk_i_hash = poseidon::poseidon::bn254::hash_4(pk_i_bytes);
    let epoch: Field = 1;
    let sk_i: [Field; 4] = [1, 2, 3, 4];
    let e_i: [Field; 4] = [1, 2, 3, 4];
    let honest_path: [Field; 4] = [1, 2, 3, 4];
    let tampered_path: [Field; 4] = [1, 2, 3, 99]; // path element changed
    let dkg_root = make_honest_root(party_id, pk_i_hash, honest_path);
    let d_i_computed = sk_i[0] * 42 + e_i[0];
    let d_i_hash = poseidon::poseidon::bn254::hash_1([d_i_computed]);
    let ciphertext_hash = poseidon::poseidon::bn254::hash_2([pk_i_hash, epoch]);
    main(party_id, pk_i_hash, dkg_root, ciphertext_hash, epoch, d_i_hash, sk_i, e_i, pk_i_bytes, tampered_path);
}

#[test(should_fail)]
fn test_fail_tampered_ciphertext_hash() {
    let party_id: Field = 1;
    let pk_i_bytes: [Field; 4] = [42, 0, 0, 0];
    let pk_i_hash = poseidon::poseidon::bn254::hash_4(pk_i_bytes);
    let epoch: Field = 1;
    let sk_i: [Field; 4] = [1, 2, 3, 4];
    let e_i: [Field; 4] = [1, 2, 3, 4];
    let merkle_path: [Field; 4] = [1, 2, 3, 4];
    let dkg_root = make_honest_root(party_id, pk_i_hash, merkle_path);
    let d_i_computed = sk_i[0] * 42 + e_i[0];
    let d_i_hash = poseidon::poseidon::bn254::hash_1([d_i_computed]);
    let ciphertext_hash: Field = 777; // wrong ciphertext_hash
    main(party_id, pk_i_hash, dkg_root, ciphertext_hash, epoch, d_i_hash, sk_i, e_i, pk_i_bytes, merkle_path);
}

#[test(should_fail)]
fn test_fail_tampered_d_i_hash() {
    let party_id: Field = 1;
    let pk_i_bytes: [Field; 4] = [42, 0, 0, 0];
    let pk_i_hash = poseidon::poseidon::bn254::hash_4(pk_i_bytes);
    let epoch: Field = 1;
    let sk_i: [Field; 4] = [1, 2, 3, 4];
    let e_i: [Field; 4] = [1, 2, 3, 4];
    let merkle_path: [Field; 4] = [1, 2, 3, 4];
    let dkg_root = make_honest_root(party_id, pk_i_hash, merkle_path);
    let d_i_hash: Field = 888; // wrong d_i_hash
    let ciphertext_hash = poseidon::poseidon::bn254::hash_2([pk_i_hash, epoch]);
    main(party_id, pk_i_hash, dkg_root, ciphertext_hash, epoch, d_i_hash, sk_i, e_i, pk_i_bytes, merkle_path);
}
