//! Noir-compatible Poseidon hash implementations using exact Noir round constants.
//!
//! This module implements the same Poseidon permutation as Noir's
//! `poseidon::poseidon::bn254` crate (v0.3.0). The round constants are
//! the exact values from `consts.nr`.

use ark_bn254::Fr;
use ark_ff::{Field, PrimeField, Zero};
use std::sync::OnceLock;

/// S-box exponent (α=5).
const ALPHA: u64 = 5;

const NOIR_POSEIDON_CONSTS: &str = include_str!(
    "/home/dev/nargo/github.com/noir-lang/poseidon/v0.3.0/src/poseidon/bn254/consts.nr"
);

#[derive(Clone)]
struct DynamicConfig {
    t: usize,
    rf: usize,
    rp: usize,
    round_constants: Vec<Fr>,
    mds: Vec<Vec<Fr>>,
    presparse_mds: Vec<Vec<Fr>>,
    sparse_mds: Vec<Fr>,
}

fn fr_hex(h: &str) -> Fr {
    let normalized;
    let h = if h.len() & 1 == 1 {
        normalized = format!("0{h}");
        normalized.as_str()
    } else {
        h
    };
    let bytes = hex::decode(h).expect("invalid hex in Poseidon constant");
    Fr::from_be_bytes_mod_order(&bytes)
}

fn parse_noir_config(
    name: &str,
    t: usize,
    rf: usize,
    rp: usize,
    sparse_len: usize,
) -> DynamicConfig {
    let marker = format!("pub fn {name}() ->");
    let start = NOIR_POSEIDON_CONSTS
        .find(&marker)
        .unwrap_or_else(|| panic!("Noir Poseidon config {name} not found"));
    let after = &NOIR_POSEIDON_CONSTS[start..];
    let next = after[marker.len()..]
        .find("\n}\n\n// noir-fmt:ignore")
        .or_else(|| after[marker.len()..].find("\n}\n"))
        .expect("Noir Poseidon config terminator not found")
        + marker.len();
    let section = &after[..next];

    let mut values = Vec::new();
    let bytes = section.as_bytes();
    let mut i = 0;
    while i + 2 <= bytes.len() {
        if bytes[i] == b'0' && i + 1 < bytes.len() && bytes[i + 1] == b'x' {
            let hex_start = i + 2;
            let mut hex_end = hex_start;
            while hex_end < bytes.len() && bytes[hex_end].is_ascii_hexdigit() {
                hex_end += 1;
            }
            values.push(fr_hex(&section[hex_start..hex_end]));
            i = hex_end;
        } else {
            i += 1;
        }
    }

    let rc_len = t * rf + rp;
    let matrix_len = t * t;
    let expected = rc_len + matrix_len + matrix_len + sparse_len;
    assert_eq!(
        values.len(),
        expected,
        "unexpected constant count for Noir Poseidon config {name}"
    );

    let round_constants = values[..rc_len].to_vec();
    let mut offset = rc_len;
    let mds = parse_matrix(&values[offset..offset + matrix_len], t);
    offset += matrix_len;
    let presparse_mds = parse_matrix(&values[offset..offset + matrix_len], t);
    offset += matrix_len;
    let sparse_mds = values[offset..].to_vec();

    DynamicConfig {
        t,
        rf,
        rp,
        round_constants,
        mds,
        presparse_mds,
        sparse_mds,
    }
}

fn parse_matrix(values: &[Fr], t: usize) -> Vec<Vec<Fr>> {
    values.chunks(t).map(|row| row.to_vec()).collect()
}

fn permute_dynamic(config: &DynamicConfig, state: &mut [Fr]) {
    let t = config.t;
    for (s, c) in state.iter_mut().zip(config.round_constants.iter().take(t)) {
        *s += c;
    }

    for rd in 0..(config.rf / 2 - 1) {
        sigma_slice(state);
        for i in 0..t {
            state[i] += config.round_constants[t * (rd + 1) + i];
        }
        apply_matrix_dynamic(&config.mds, state);
    }

    sigma_slice(state);
    for i in 0..t {
        state[i] += config.round_constants[t * (config.rf / 2) + i];
    }
    apply_matrix_dynamic(&config.presparse_mds, state);

    for rd in 0..config.rp {
        state[0] = state[0].pow([ALPHA]);
        state[0] += config.round_constants[(config.rf / 2 + 1) * t + rd];
        let sb = (t * 2 - 1) * rd;
        let mut new_state_0 = Fr::zero();
        for j in 0..t {
            new_state_0 += config.sparse_mds[sb + j] * state[j];
        }
        for k in 1..t {
            state[k] += state[0] * config.sparse_mds[sb + t + k - 1];
        }
        state[0] = new_state_0;
    }

    for rd in 0..(config.rf / 2 - 1) {
        sigma_slice(state);
        let ri = (config.rf / 2 + 1) * t + config.rp + rd * t;
        for i in 0..t {
            state[i] += config.round_constants[ri + i];
        }
        apply_matrix_dynamic(&config.mds, state);
    }

    sigma_slice(state);
    apply_matrix_dynamic(&config.mds, state);
}

fn sigma_slice(state: &mut [Fr]) {
    for s in state {
        *s = s.pow([ALPHA]);
    }
}

fn apply_matrix_dynamic(matrix: &[Vec<Fr>], state: &mut [Fr]) {
    let t = state.len();
    let mut out = vec![Fr::zero(); t];
    for i in 0..t {
        for j in 0..t {
            out[i] += state[j] * matrix[j][i];
        }
    }
    state.copy_from_slice(&out);
}

fn x5_3_dynamic() -> &'static DynamicConfig {
    static CONFIG: OnceLock<DynamicConfig> = OnceLock::new();
    CONFIG.get_or_init(|| parse_noir_config("x5_3_config", 3, 8, 57, 285))
}

fn x5_10_dynamic() -> &'static DynamicConfig {
    static CONFIG: OnceLock<DynamicConfig> = OnceLock::new();
    CONFIG.get_or_init(|| parse_noir_config("x5_10_config", 10, 8, 60, 1140))
}

fn hash_internal_dynamic(input: &[Fr], config: &DynamicConfig) -> Fr {
    assert_eq!(input.len() + 1, config.t);
    let mut state = vec![Fr::zero(); config.t];
    state[1..].copy_from_slice(input);
    permute_dynamic(config, &mut state);
    state[0]
}

// ── x5_5 config (t=5, rf=8, rp=60) ──
// Used by Noir's sponge function.

fn x5_5_rc() -> [Fr; 100] {
    [
        fr_hex("0eb544fee2815dda7f53e29ccac98ed7d889bb4ebd47c3864f3c2bd81a6da891"),
        fr_hex("0554d736315b8662f02fdba7dd737fbca197aeb12ea64713ba733f28475128cb"),
        fr_hex("2f83b9df259b2b68bcd748056307c37754907df0c0fb0035f5087c58d5e8c2d4"),
        fr_hex("2ca70e2e8d7f39a12447ac83052451b461f15f8b41a75ef31915208f5aba9683"),
        fr_hex("1cb5f9319be6a45e91b04d7222271c94994196f12ed22c5d4ec719cb83ecfea9"),
        fr_hex("0a9c0b1916a8e41d360d02e6e2e5d1b98c34dfcec769429c851867e46e126fa3"),
        fr_hex("1dd6ba3731e49d21e8d36e9d4d1edad245ebf9bdd9ebb60a252e4804a6390f6a"),
        fr_hex("24ae2a67c3d521c11a11b7112abbdee30647107b808866a980837d0d7da4e3e0"),
        fr_hex("0d20c9310b5c14d9ef12866af5a45eae3ca9be16d200497066c8b2ee96781d70"),
        fr_hex("0e047c9821fe94d55d400d763a66c4c6169993abed543c7284b4a35430019445"),
        fr_hex("29474ab799b1e13948eff41d2ce79bfad335d09110157076988ac207e10c81dd"),
        fr_hex("03899f139d0dc4b281be3b74ab4c70789b7f41e7aca47ea2722a20d79afbca93"),
        fr_hex("1866624f761ab8dd7a91c5f37af5e47639951d5acb6b1bbf3b96ca273f71029d"),
        fr_hex("13c119f36718f7d5f09ad8541325a13acf6b34db6d9ee2af7ea06061240f3009"),
        fr_hex("0e4a1008158077402b11f13c08890b739643cc8e93fa44487b5a1575dd867fd7"),
        fr_hex("0ef505fd44ac10a251b670dafe14cabd9ada9e3002210ac9c3876f37de4e7ad8"),
        fr_hex("1d31e4e2a5978b7491c43d367470a5a5d1445b6b8129a5b9a6fd238405720de5"),
        fr_hex("0a979ad5428d481cb624d9d504524a9694ca5cb4421b5d1dc6af2c030fbeac39"),
        fr_hex("0f7fccd2ec8bc6ed9ce3682f38aa291deea9373f4995778bf762ade36d6ab2a0"),
        fr_hex("2691b924dfa123005f7c078d9bf8706defe99c2ba99bd6ee53b153e9fec7bb80"),
        fr_hex("02077df6510b4860e56b913bef3a80dbc464b0e4678add60dea7a9517463220b"),
        fr_hex("29ee09d8af9d24ca49350ce2e0aa47d00a3dc21bafbfac1c9ba61c58e2993e8c"),
        fr_hex("08b292c661d427506b9a01916624f3cde332aaced9f1a494a733cea6f25bfaad"),
        fr_hex("2583699ce536a757b22e4713edfbb050092c84abc72c90ad87393a1da9a4cf90"),
        fr_hex("1e3f1b660223d65ad88999475374f6e25fd4148eb8110a0b12cffa19657b0b66"),
        fr_hex("20f3ecbb37c34aec79131455461259e59b222f0ee8e02f3194cf62a9ad4c3448"),
        fr_hex("0df4f5088e4444fbf87d553ba62dbda95696d8b9cf6210b1c85513b1776fbc64"),
        fr_hex("02b348effd4c9cef00a1cf4dd67dd664b2ffe361a807c589a252c63bcbfc6833"),
        fr_hex("1ba1e522fcb153676cd8f20e82256f0327c000fa96b1b462fc84b556f26a86c7"),
        fr_hex("0294c44df8e68c96144e964c37bbc5766764ed3550aff80dbe9d3fa74419fe50"),
        fr_hex("0313716eec6dcd8a602ca040700498dc04c77dfe2194753c59bc818c1d2636a1"),
        fr_hex("287dec74696d663e2359f68225de955384d960bbafb90967429a442e19e3ec61"),
        fr_hex("25e42f72c6be0942311ba097cf365683db4962c8204fec9213f0f8f72c1946be"),
        fr_hex("12b6881b96654fe1768c242acd5399b08639f081a94896f5ea6da70b6b475c91"),
        fr_hex("0dfc2b54546fd3267d7be55c716cb243ef18118ed9498c8270449bd9418afdb5"),
        fr_hex("27dd55fe0d5c0ff56ad4890fa029c27c5f36d04cdc73899ab99b2872b28eedf0"),
        fr_hex("0c60962711aef16e7a2ce59f587443ec8b41ef8dcfccb38188adcbddd32f173f"),
        fr_hex("2edc09feb267c6b586e62fffe32bf5f16c28b585986b81116684b7e8b40d42d2"),
        fr_hex("0af8386859db252ff295a19466d8d100622c90502137aa1cd4c4bcc9656d11e2"),
        fr_hex("121f218392f73d4c16abe382102a459e6c080b3ca4eda51a23e651a13a680550"),
        fr_hex("1ea38273f5d59e65061f8c775c571ffc75ef67d29405b5e02913cb3019d56f8e"),
        fr_hex("09bd2349005699bcc0ac35b627e2f8f08bfc3b0bf30b146f37742ac1556187fe"),
        fr_hex("091c505b1e92448c11aea22aaac4d44f6a7f2132f89e91b7f55f9404696c1433"),
        fr_hex("0b316f1c29689d4f490f7fcdd5e9f2d256d443ba14cda4bb799b0573a931a99f"),
        fr_hex("2049251919a8f3f4398188b81f99d2e2d0e3f5359cfa55bdf3aa75fdadf367e7"),
        fr_hex("1fe7f9eb6788101908814168e3e4cf7a899a105bf9e584af0064188a4aac55bd"),
        fr_hex("158e6579b0388153b0acd630ea94de8f6d966d529c2d01b9e9b1c67c1ec1d570"),
        fr_hex("1994f82f27153afb9de2aa3f4be05c4b2c487e393dcedca2566aa6b7fbc3696b"),
        fr_hex("1b6250553e8629a5a8a40b568432ce7dbd83c87603eeccc8dad572ccebef6e1d"),
        fr_hex("020296940a7d1eded2ae79fd78fa2ac11abb2210bf24542feabee71f0d0d7c9e"),
        fr_hex("2553943f9e0ffce9c297cd31c29f1fa5f01883cc9e504fded7a905032c170c89"),
        fr_hex("1c56eb362896c2f00ad18faeaf04d577f5feb4db4e077965c38f2eaf5f7be08c"),
        fr_hex("0ed8857205e0680055de7e822b6f7d62ac0f75fef67da1ff7b7735208885cf90"),
        fr_hex("0118f91185a09355f9d8c3f556367a2bebe79e7d9528a8d72a592681671aac75"),
        fr_hex("2a71e6a67abdb25a78010fe6fe0a20d1d84e21cba75ad55937dc1834c13af0c5"),
        fr_hex("02327dbc05997ce8575680e4b8929d4e9ed25fb9204277d603061986dbee57e0"),
        fr_hex("0e05235e01f21cc3f2971c382d18c14e41785a5ec8d447cd93d13281792e6d6e"),
        fr_hex("098afa2ea7ff065b2adfc4ab00f3b04496c1e490eab264d2370b107e5a49204e"),
        fr_hex("27bddb7bf06eaa63419adae44209dd25a4e35edcb863b009bd34ccc4905d204b"),
        fr_hex("2704406bc806f4ccb19085cb9d3771b12ab5ce7aabf0601e9e06a2bc98837ade"),
        fr_hex("21c75c54664b9fec86756aa9027261975244f42cf91c9cc0b33c2a62b756a3ef"),
        fr_hex("2be84c1d84c16038ea5f933290699daaaa8164c5ea39a02bcbddc66cf69fe8ec"),
        fr_hex("2c970e41d48649cf013c676c8c688ac165563720d1d5f32628ac5b239488a96e"),
        fr_hex("0e1ad2660a2e958daa1f2654b3a37fee60546ca0327150733070742edc806435"),
        fr_hex("2060ee7fdf775fc7e389a55376374c9e35d5c8763d597f426304e236f577b829"),
        fr_hex("1e0116818c843ed86f09daee0a581af10d52deeadad77656e736eac08e6f0f17"),
        fr_hex("0a89c1498ef25a383d886bb58424e6940ac399e3e557e9de951a697c54a7576c"),
        fr_hex("0303743d6f36d925e1097483350f5bd2cb297d4ec9239209f63c516b849a67e6"),
        fr_hex("08cf44446d968430232df175d462b9c9b0e2e2c37e8406764cb96c7c3446018d"),
        fr_hex("2419811cbaeb3f551b0a9232eee5d53e3769fbcf5239533074375f1b00777f16"),
        fr_hex("004237c622626db376b774849dbbe876809082f1b13f5824f4c58369f27fe7b6"),
        fr_hex("1e5b490c72eeb607e114a5cb87a8494b178937cdee34b9e8e947342c14454558"),
        fr_hex("04265333e59e1a5ff749203cb4a5d1415a72862c61380b1c242d0f32ca15b97a"),
        fr_hex("189deaf74258451ac4da682532be43d24a5c683293c1ff7486de26d35d982e86"),
        fr_hex("04ec516b0fd42fa53a34905cfdedaad021b36399d03d8263ae08c46af3eca76f"),
        fr_hex("2ce1c8a00845a82b3aa1b6642fc988578576cef86196525e6d595c7701ad700d"),
        fr_hex("247816fd0d34f9d3b396917478605c94a1c052a6ed663bdc344e7aee9686b6b4"),
        fr_hex("00c676dbe6c494d5609c444de622bcf60cf555091a507fce86477019daea987d"),
        fr_hex("1cb395ade530fc2407aa7b2148d2dfaee30f4ddf258fc149cce3c5cde80a85d5"),
        fr_hex("190e1494e3cfdada3b9e65d8fe3c1ec769540da023f9ec2e56259f6a56890b0e"),
        fr_hex("18f2941b2335138336c351a792343222a845ee0a2ea5a3b9160c1d6d9b229fe2"),
        fr_hex("14ea23ce8b2312e07df57e0aece1da5d2c0e01f757e6a5c86ab5e403688544dc"),
        fr_hex("2818ad1005f4efb5d554361a29f85ea10940d6e71f38e8369beff3563a660bbe"),
        fr_hex("23ce3a9a522915a281793977b49054c37d65f90b841e0ca90817bab49d79db4a"),
        fr_hex("06c2ed2be876309a9b3b44ece37b1c42382927dd04249658a3d41e3f38d5e022"),
        fr_hex("18b6740f72d77ebcf642b945ca2ed6c8a9853a3749d7fab6051e4ca36f44fc42"),
        fr_hex("1feacb9eb2a6878061374d069a9dae328369ee63e75a1b99cdb06a48b0d9976a"),
        fr_hex("1a44ee4565a967647300c75ed2b2543d8d45d5477fd606a356d1073bd13831d2"),
        fr_hex("041f3b3b5b1050c16bf3d62d87d5d273b067da484679103231ed65a18da9fe48"),
        fr_hex("1fd958cc4fe0a290bd0fbfb8b8a513acb5898d63bc0d7e585b7d081c49eb5659"),
        fr_hex("175daba07c5edbf84f09c87a8c34dd73325943a48fc12cb839dca47512561d2e"),
        fr_hex("09cf0a4e6e31dc24dfd5a5a27a77833e477d5b2d92cff5fc5ccad9528c43ba78"),
        fr_hex("12d49465bd4120cbf78e5a3414d44c6530bc963bd701c54d4c6418a6cebe80b1"),
        fr_hex("101b2f2b675804d3b26b2bd1e07c7365af0bfc2edf010916eefb39e28215d44a"),
        fr_hex("114fc65faba09a59749e0b5f111930783529a0638456216232cb7e5a339736aa"),
        fr_hex("1dff99b52799afc802c2bbf9b67dd044d3cb51017dc4f88358ddd67366d3a9f5"),
        fr_hex("290f4496a52dd4dda59edccd7325038bbdc0554ad3a9a0be7931c91062a67027"),
        fr_hex("091e8704663c516c3b96721d2033d985089fb992dca48c8ddcb97d7d15c7e188"),
        fr_hex("2dce22599de04196a0169fc211d0f9c8692643aa09728eadf6d50bb534c0e323"),
        fr_hex("29a7ff0720e170c0e67efde72795328fecef66daada5f0e2ca858a8c6135fd48"),
    ]
}

fn x5_5_mds() -> [[Fr; 5]; 5] {
    [
        [
            fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
            fr_hex("2a70b9f1d4bbccdbc03e17c1d1dcdb02052903dc6609ea6969f661b2eb74c839"),
            fr_hex("2f69a7198e1fbcc7dea43265306a37ed55b91bff652ad69aa4fa8478970d401d"),
            fr_hex("0c3f050a6bf5af151981e55e3e1a29a13c3ffa4550bd2514f1afd6c5f721f830"),
            fr_hex("2a20e3a4a0e57d92f97c9d6186c6c3ea7c5e55c20146259be2f78c2ccc2e3595"),
        ],
        [
            fr_hex("25fb50b65acf4fb047cbd3b1c17d97c7fe26ea9ca238d6e348550486e91c7765"),
            fr_hex("281154651c921e746315a9934f1b8a1bba9f92ad8ef4b979115b8e2e991ccd7a"),
            fr_hex("001c1edd62645b73ad931ab80e37bbb267ba312b34140e716d6a3747594d3052"),
            fr_hex("0dec54e6dbf75205fa75ba7992bd34f08b2efe2ecd424a73eda7784320a1a36e"),
            fr_hex("1049f8210566b51faafb1e9a5d63c0ee701673aed820d9c4403b01feb727a549"),
        ],
        [
            fr_hex("293d617d7da72102355f39ebf62f91b06deb5325f367a4556ea1e31ed5767833"),
            fr_hex("28c2be2f8264f95f0b53c732134efa338ccd8fdb9ee2b45fb86a894f7db36c37"),
            fr_hex("15b98ce93e47bc64ce2f2c96c69663c439c40c603049466fa7f9a4b228bfc32b"),
            fr_hex("1c482a25a729f5df20225815034b196098364a11f4d988fb7cc75cf32d8136fa"),
            fr_hex("02ecac687ef5b4b568002bd9d1b96b4bef357a69e3e86b5561b9299b82d69c8e"),
        ],
        [
            fr_hex("104d0295ab00c85e960111ac25da474366599e575a9b7edf6145f14ba6d3c1c4"),
            fr_hex("21888041e6febd546d427c890b1883bb9b626d8cb4dc18dcc4ec8fa75e530a13"),
            fr_hex("12c7e2adfa524e5958f65be2fbac809fcba8458b28e44d9265051de33163cf9c"),
            fr_hex("2625ce48a7b39a4252732624e4ab94360812ac2fc9a14a5fb8b607ae9fd8514a"),
            fr_hex("2d3a1aea2e6d44466808f88c9ba903d3bdcb6b58ba40441ed4ebcf11bbe1e37b"),
        ],
        [
            fr_hex("0aaa35e2c84baf117dea3e336cd96a39792b3813954fe9bf3ed5b90f2f69c977"),
            fr_hex("14ddb5fada0171db80195b9592d8cf2be810930e3ea4574a350d65e2cbff4941"),
            fr_hex("2efc2b90d688134849018222e7b8922eaf67ce79816ef468531ec2de53bbd167"),
            fr_hex("07f017a7ebd56dd086f7cd4fd710c509ed7ef8e300b9a8bb9fb9f28af710251f"),
            fr_hex("14074bb14c982c81c9ad171e4f35fe49b39c4a7a72dbb6d9c98d803bfed65e64"),
        ],
    ]
}

fn x5_5_presparse() -> [[Fr; 5]; 5] {
    [
        [
            fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
            fr_hex("12873658ecf188d299b8ccd568eb14a4d4307c5caa95633dc296f05cfc966598"),
            fr_hex("153cf8033d8e8a15cde2c5e6b93da4018c5954d00a9274ec5ec6d5101ea22761"),
            fr_hex("09f15a882446823fdca6f6ab15dd8e250d90c84470516671afbdfb0de80fb00e"),
            fr_hex("167c655bf6cf3e0fb64c9075773bc862b24b4ce2f69c8ec198add2758a2ce216"),
        ],
        [
            fr_hex("25fb50b65acf4fb047cbd3b1c17d97c7fe26ea9ca238d6e348550486e91c7765"),
            fr_hex("27f9160806de9ef57ddb4243f839e4b7e8bb293ac176fdc5b5419ed73a07999f"),
            fr_hex("16fceedd703bbbc2bc6f1d792e501939105b044b1b904d3b110110da983ccdc2"),
            fr_hex("2eaa925d06b6f5a77c0d5cb20598742791495cec84593a57ee9fc4c9115ae7ca"),
            fr_hex("279b324735fbc883e24f191ca7039f9986115b9e6fcf4946cf45f08ceda2dc8c"),
        ],
        [
            fr_hex("293d617d7da72102355f39ebf62f91b06deb5325f367a4556ea1e31ed5767833"),
            fr_hex("097d71f1fd579a0d0f436a6b36165cd23a9fcab03ad25e7872cdb09b4a0ea0dc"),
            fr_hex("1a9fd26611128d592d594f51c251dbf4eff6dccecbcf2ebf310e34bed661337e"),
            fr_hex("21eb30a57e5912ab06d18573fc546b2bf3be840d5f5ede01f91dd2bbb578dcc2"),
            fr_hex("13abaf72889b31372b1e6f48759371ef65bc57d28ac2f60e6d227eb008b96ced"),
        ],
        [
            fr_hex("104d0295ab00c85e960111ac25da474366599e575a9b7edf6145f14ba6d3c1c4"),
            fr_hex("19bb8abf6a012cc7b8b974039c6be6df31446a51702b39a8d90ae4be7ec33ec9"),
            fr_hex("11075889bc0dcc9d6f06af3012f04aadcf9049de04fc775f8fa091702e70b9bb"),
            fr_hex("2e4cb25599a3dbf07de338827b28d16b9c8fcab8fffe8f2a16161be6a521a358"),
            fr_hex("0c7a700b33fb23fc642e0e8671deb84d05ded8ccbc968d15171182e158684e85"),
        ],
        [
            fr_hex("0aaa35e2c84baf117dea3e336cd96a39792b3813954fe9bf3ed5b90f2f69c977"),
            fr_hex("2b5d28e8d648bffe0fab59e3c7d983a4099fa0a4c548df0006e6d0f4e20206c1"),
            fr_hex("1a96c37c461ab8a38ee15bc2784c5096d30d1482e57c2f861bab95584b90d84a"),
            fr_hex("0dbdd3171308bfcd3cb8b8a676592858b8652e902142beb8fe4145002fba8e0f"),
            fr_hex("17ac4855f295a3b8fb8ceded7f4b39290647a0145af56b03b01e957808d66fa7"),
        ],
    ]
}

fn x5_5_sparse() -> [Fr; 540] {
    [
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("0351d582486c39726623750495e297970b0e19787b49173a9388a0d5b08788ab"),
        fr_hex("010e1a3beae297a472a31a3b51514c664abb12ec2d15860a29d2a9352d3ce8ba"),
        fr_hex("12395fabf1c14664faf3ecc72a84623c1d5cb7b5e5744e602c886a5773e5f06d"),
        fr_hex("09b91873151f00b299a173a5b736f73fbe2ce543f0b4d237565bd58758935cfd"),
        fr_hex("01d53cf618f93c90852172c773264b8f49e938bf22791cff829e95ff6942299b"),
        fr_hex("1a78e48450798918f254396fa7417bf2c5ff69259200c2a8d53af5f2c4d8ba1e"),
        fr_hex("000d3d4c1eb9828c87afeca8ea128d1d533750cf555c6b70d70a8520ccf16feb"),
        fr_hex("03af062fcd1ca71ba6de0ca4436f1a5a0698a3f49abbe4ecf3daa0ea2e4dc84c"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("1ad1ba4f26d401924b25657414256b59767284a692897ba5cd53a7f5322005fc"),
        fr_hex("1133694747d2cb4890f4f5982564eac6019ca5a9091b302d2c10b87297041d5f"),
        fr_hex("1b46c42ff1aa475972e26f559a88164024234f7b392039fb2a2171be631bd8de"),
        fr_hex("1954aa0a79f14968c817000929e2e744262871011f238d986086e7d9574936b4"),
        fr_hex("07aced898db99ae9796fc7191a103b9de4c77f0e08ecea6aa593974f652ac4ba"),
        fr_hex("18a5a098d914f6221726d42ada7683a1605e20217a09489c9b2d84c3cdd2c39e"),
        fr_hex("13e00cf4ab3b1e028165af8d41019ca20a21aeb40926592a180f9806083eb5a0"),
        fr_hex("0478f72938b528ec79defe09215b46320801fb752ddc88d638a48790561b4e2b"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("08ff43b0eda2134077b96d7e4cc37a6871254910ab4c58a4bcc78c1bc6ce3937"),
        fr_hex("27d7fa3ab9c438b6ad1ec5a60e8ad91aad02e4d2908ff7192e5ac0cebd91f928"),
        fr_hex("1e9ac8ae7cf2b40d629999251be50d9771391326a664dfc206f2abec8efbe56f"),
        fr_hex("2d6b56b4849de82b636d81f2e98476bb6c35cbc8962137b615bff86f8f261971"),
        fr_hex("21e70566d2f4bb8728fdb3749da99a2143a0d90bb6c1b0d6d02125aa1fe63092"),
        fr_hex("1c01c050dd9b0b8ec8e5ee1eaecac1171bf69a8f3d477eb7ec3a605b010d4ea5"),
        fr_hex("282e8dde73a0dc74ee10816aacc1dba10c142109c14ad7954eb7b56ca268a16e"),
        fr_hex("0767cf96b16035a96d19fcc57edcd92e746d226cfe84b733454c7ff9a16d25cc"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("18974b9f253b6bb681f82ed0f2d3e6b4f70ca858468b7f1bd3ded1a581ec21d9"),
        fr_hex("18153fe8966abfc450a25222a6a27f6175fe851989776dcd2111a5a2de99c2da"),
        fr_hex("02da1e2e775539490c2fe2c827e65c00e382a4a5d6c49a8374381d39c627f36c"),
        fr_hex("2608589b9cd3f4c12b4e832e05fc5ebdcb403cd6560a8d7ece8d17ac94e79e06"),
        fr_hex("05b4b074edb1366d35bf1c1ec1451a36cff351b407a8d30d563471bde491f146"),
        fr_hex("0856cc5a00bc37dd0217920da66c5765dea0644555e35822d7fd464d9eb38096"),
        fr_hex("2021dde3ed193bdade457c9db5ab799e6b3fca640669d2f6295b4852f54d446e"),
        fr_hex("12e3785f05f36bb797b2c9f03c5a55fab52e88b0550b7155d6013b706574d41b"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("118084c76d1340b3980add4df3878df4ffc6e9fe26f0b5c4e2f9579ee6fe2c1a"),
        fr_hex("0b9dacae8623c514c622c85753ef7b994d9102ab46620f956c26e9c62fe53050"),
        fr_hex("0daea6d18a826bb2ba972ae16dc621cb8fdf9ecd531ee3c9f9d0b4012da6769f"),
        fr_hex("08f2a5df6437e253b579921fc3208b3c176e5a18dde267a4f85b7afb7f79ceed"),
        fr_hex("06a91d7c75e34fd43d9aa53b7d2793e4d5d70a5fecc5fd5653b162ba2631aa68"),
        fr_hex("207579e33c36af2d20d759996c313f78dc339878c0a289d5db58b6b3d6069c56"),
        fr_hex("25562540cd12084b3392c8cb8cda95ffc9c2dd6f8a75054ce16acf87ba871b9f"),
        fr_hex("00bbf47feca60b93dd0501ee0fc294c2a82b103817b4acf0af6979183afcdc87"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("1e0814ce223453b24804a1ab4ce39815e35aed2fe9f7510e6288abb9d8b15711"),
        fr_hex("18f9aa2721d95963399ae18d6d95a6f81b78b528e750554eb2613d6dabbd72a9"),
        fr_hex("2ea329822ad302ab8831c559c64080e7ba6bf4c98ea0caf9cddd929bbb5875a6"),
        fr_hex("29910d86bc27b38a93bca80677a3647c01cb5262ed19cd0c00872925a046a338"),
        fr_hex("021c0a05ace45015ea895e01d630ce6b7423f3c211d26e8b6ef54d3dfc0660ab"),
        fr_hex("025e7c463042f520ed2ff8c68be30bdddbd7ea5cdd7a91224bc6a32a3f5c0fcc"),
        fr_hex("0df5b7e7663197f911e0dcd1ff4237ffdf080234e9b92201538ae7db6b6a7d21"),
        fr_hex("094d0fcd9592b4771d2b9bfbc2bd78defef3b6ca923c68382650f9d63ce37c85"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("270361108967ed0391a49d4b7cd6af9bdd544e8bf048658c4fab36aa12407263"),
        fr_hex("18bbf89e7cae93044c847bea654101914dbdd1656483e54e07ae332857821961"),
        fr_hex("04aa47a0ede64ecdfa83507a2b8947b4b587758d75239071f6b4d3d66777bc1e"),
        fr_hex("182d30ec988fca803ff7def1470c06aa6a596f56710184909fda17d354d3ce02"),
        fr_hex("223c27171e456846dffc59cb1a53c761afddf85582e4c70ebafddf10eb1f8448"),
        fr_hex("07d46dc97554a25edb78ea4d862c48bc5a08e9ea1eb369c5c8c2e0903114c915"),
        fr_hex("1bf473a2e982e519523b486d264941d8e32cbbad362bdbf736d7ac04c4d2a964"),
        fr_hex("12277b175bf54c3f2b0a57eb189e77714cf21630ace1fcf44d39397aae5b6da5"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("15c0a2cfffac7feab86a185031f489a9f83e89e3337a84b51dfe6fbb57feb15b"),
        fr_hex("2b83199ec584185de52190f5a415c1fbb9efd4bb9eae4c4e2763abcf99359ccc"),
        fr_hex("28601b9940a312c65b02adccb76937ef645d4e451c940ad4241b2b0f4925d7da"),
        fr_hex("1a187b4875be24a2420729e016901b94ec0566c8a6936978c3f21e8d611996f7"),
        fr_hex("10ed1fd44722d10bc7e44824e64978d36e68d56de2a465a0201b8e31065d5c57"),
        fr_hex("2c4b6867179a949d377a9bfd3efe48456f7e70f02d859c78684a3573486dc227"),
        fr_hex("15cb2c17aabecf7aa0f61655a8bb35a7afd87d0e20ac38fe21a07da7b388dfb1"),
        fr_hex("04dff03c742111aab3e61f4166a733e87699c1ffa889fce179316e39f7d845ec"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("17baac874eaaa88de70cc92d5a72e00be4ec0e5e99ba7cbac2b0d98cead394a1"),
        fr_hex("1dba338b4779919a2fb22ba949a050c85a73983d5ea4752cd73f664fe05f6247"),
        fr_hex("1e33e7fcc41f32f90de5771d69e58f4486290c7b856becd5cd967d8e7739f719"),
        fr_hex("10877ad7cf0652a2ff93977d3862e3ffb5d87d0c040f02a4f98612afafc9b604"),
        fr_hex("115d3675856ff59ebcc9110defb9d6c70df6af533d4b0875d0e5eec430350595"),
        fr_hex("03d74b961ba9013a874e7bcdc782f478da6097537549db7e6af4702ca749dae5"),
        fr_hex("2563411e29867500a8fd18e4eba3c9a2b7992e44d263c29f7e06000f74887cdd"),
        fr_hex("285501c4e0ee1b3c3e6b1b29160d6ec0f1af4dc2f36a4a1e654b7b47899738d7"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("209194489c86891b179e33103a81d969c5c75e941dc30e7228c04ed8ba68704f"),
        fr_hex("2c7b2835cb79c29852926900cc168b2315aaf03a89532dd9fc162c2f7ddad845"),
        fr_hex("1df181c420308c5b0bf00ee21c16f248edff686e9e835869d1022dcd4a8a635a"),
        fr_hex("1ffabdffee2481d8cc1233506f708d9acabc1d758bb99c329142c866ef4c7474"),
        fr_hex("08955ed55c2bec07027e4355a694a9b6ae1d9d50126563b29d8a074ea65540f5"),
        fr_hex("1ab4b24a4db7c5758471846eb375163e7587791417cbc355b6ce93b64fd01da2"),
        fr_hex("25a3439d2838ad459270bc633164f3a68215e11217eef1d605ecfa8b1805c609"),
        fr_hex("065240d63179ae83013295a8251fbe17dd988ca5c84761ccb6a6ecb2bfbf02a6"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("0c1a91ddc1b24113bf876a2ef895c3315cd1b109cfa569b79f3155ee12b1c564"),
        fr_hex("146fe8e28539ae36ae921069f4af83f675f1b68399efceb18989cab5fdd36ac9"),
        fr_hex("1ba8c3cfa46425412e30790090980db139810efed7bdba7a38adf75e1a0d3641"),
        fr_hex("083a58c9d889b74e66636bb8418db624726b0f1374f59eafb4d269ba1ed234d8"),
        fr_hex("2b812a76ea526ce18df6032192ef033541aaf99d1c61839a0edf0336142a25f3"),
        fr_hex("295f6d35fb9e57a50a5d913600538030ba8c09e021c16aa8634488cc8eeba645"),
        fr_hex("1de69ba07e3b9f90c87eb67b1f64660c71befe5138061dbebb752296032542e6"),
        fr_hex("24734fa363e52c64ee0162a86578ca899796e89caa1a3a3533b0965665208f59"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("2d5fb67efe93e8386fac071fe3522be1dade9dbf1d1030417a7b51e3122111f4"),
        fr_hex("19522e9228feae7473e317fd7958a021a0b042a81b75da6dbf7568b857afab75"),
        fr_hex("2bc3f6f0df0c7305afe83fd9ef0b708e129fbe889fce42cb695b33b290479342"),
        fr_hex("0783e5635eea0e623bb8c406909f0db77ad4f9302d4828b51015d6512818690e"),
        fr_hex("2d61b243f02e21edaed6fd2e4969ddb95a6d0da8db17d115a9a3b0d8885bccaa"),
        fr_hex("055e1a09f4bd4809a86e67f99279fc06ca89a4468df1ea25d76fe0ad36ccea12"),
        fr_hex("17871eed22b0cdd2de61e55ba5c9f4e37da63ed0376420bb1ee7f077a0d7a85e"),
        fr_hex("20fd0af1329bbdd70d4d835d18c915d98956c5f0a4252cfb81c1fe02fe130091"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("2e5b840ca8faeba6ec3613e22eb7b071d9633c83cef659ed96b2f6a8fcc6b262"),
        fr_hex("05f5385703edf7c4a388ce585a81fe7cc92ff49e900b5601865a352c61d6b111"),
        fr_hex("21e83ab5e95d369ccd30cc1c55cd5844cb1cc78ffcf0c8bc91c9c0d9937a3fab"),
        fr_hex("0a67b7ed9c37946306ac525597f1275b30a5d004ca50258c3d992284d90d724d"),
        fr_hex("214f52f9f73a2c2d5425c9610461303d839dfe71891489c376c2ea3b5d868b27"),
        fr_hex("241e0d267f7d1d899656929cdebd850f70ace216d9ac10253ab720bf40da0c7e"),
        fr_hex("2229153475b7a6b282e110b10e8aed1fbc2a05a37352e954f40d85205fbd8bef"),
        fr_hex("0f30d0b7cd8ef10e895cdfab3faa4f4c1a61a5f4eba688634540619c84782d2d"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("265589a340c71d49e1660d3dd43d1869408176d8b9110ae8c369078de8ff7aef"),
        fr_hex("1bcadf844bd1a2e7f4f464991dd651b9f15630c94977d35ebc3e85801252ac2e"),
        fr_hex("0c112b1c56ea288e8518cc039fe050649cf40b7ab98de8fdbc56eb7ef6bcfdde"),
        fr_hex("0f020b9ef75af8ddd505cd3947e11a04270be15daacbfa76fa04d9005283aa77"),
        fr_hex("0a426601ce9415e666acbbaf2a7cc8ef7ef7d07538d84b1a53da24c19c601688"),
        fr_hex("10a1af65503614381fe2003123aee9008ab97d69739dc462e72a8be04594618e"),
        fr_hex("2d792f9fe5f0ad658dddadfe3893d158012d84b3837b7415e188131595b060d2"),
        fr_hex("2daa42d04e0b62fcb3869031bf382c3b9f8a98f7f5bf7421d0b63c2598f5f65e"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("144c0395157a1bfcfb5cc4187f271096784dbcdbfcb6a28c31ce8a06f908c0ac"),
        fr_hex("1af8cdba0eccc83c16019622667527645e94c9ce64add4415df7f40446277a09"),
        fr_hex("213c7a7ad6237e7211530c210a8d6f46a25bee433bade010591e6adf42fcd906"),
        fr_hex("224f1ca24803c0119ad0e6c41a64968e064a83f5821972f2a5c9d5895da4ea42"),
        fr_hex("10944d95ff5a3699efdde41ead13344937e3b1b93ba73a1531246ca4b99aad2b"),
        fr_hex("0cb2508b0a3395fabbeee5286ce5f1839c006ebbc09d94f475924923d8079ec2"),
        fr_hex("284a14b1007ff6c5c0f8f7d8d0e4b19fe2d4a7094103912134b0f563a672acd1"),
        fr_hex("2bc0bce43d55bfe1a27eed426980cf9055b0dbd42e8de516e77580b9d9a9060f"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("28e9b1884a4619b38b6f8a384368c358b7f210f3412c4481a26ae296f73c5c72"),
        fr_hex("2123ca1f119a35e7d4e1b323fd2942d12ed020ccff3a7ad6b65af90457f00614"),
        fr_hex("04aaffb0ba008fb9a82fc0700beaab2ce39efa895acdc280252f01e31035b8ad"),
        fr_hex("1f1e16f8ec9261c82443b9b31cd908015e2c2d2314629a22639af1f37e1073d8"),
        fr_hex("134928ff5ebe5e019214ef937b7f7a28248285d583613ea2bedfc66b5e2ae924"),
        fr_hex("087fc99e11e63deec9d55047ac98030c57a4f09228cfa7749a3e1c7ab5f212e7"),
        fr_hex("09429bcc52d6c43814df5b07fa116f8875299500a36ef791b592a64e27cca486"),
        fr_hex("2267b1dfa5d26e6f0a80bc8b4c0026f0204bd4fd06c7725544d7760354e401f4"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("16fb3cdb76d21d3448c9988f428d198c8e5a640035ac2caff7aa7964b34ff1dd"),
        fr_hex("080dd9d263a6698479df06bc98fc64594478028b61047ff93c425b29b092d37c"),
        fr_hex("165f4f2d302a24eea5f46abeec4ab03d21e3d013865085e515bebcb2684af340"),
        fr_hex("0a8a3f3abf28f457c62045789fdcd302f0df1049b6ec521db2b7e72e8d9516cb"),
        fr_hex("2342f103587a005c977578b12810378f9014bae831809cf7ad59ef3aed48aae9"),
        fr_hex("1d1308e311e7ab846e158769c12213013eca377f396061aada6220f29eb1b7d8"),
        fr_hex("2563949aeabfaa782be07dad903ebff5c913893761b75a3f8402a1e2bea5a998"),
        fr_hex("0cb371898d8d2e1f5bbc32dc21782704a73e415e0c9f6387157b48746bbf6ebe"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("1231d40e7c6fe5bd47010ebe4f63d186369cdb6e8823aec194093a0b4cbc6845"),
        fr_hex("018943696a4da551747068255f57a0437ba0ec36ad7e5c92cbed9c49a9775b97"),
        fr_hex("1fa58f378160dd4af40e3b01bfe32dfd34f2cdca527973c194a53af30bc40670"),
        fr_hex("0c976561eeade533c5579041bcf5e8272e4af95efe3af9e5372250fdc5ad8966"),
        fr_hex("0cacfeeae1a8359ae9fcf831f315a4b8c576d579eae86b1b09823656231d3bff"),
        fr_hex("109b0647298eaec354e4a155308192b5facfb586bc2fe63f073cd221a2106fb4"),
        fr_hex("069d4744aca289d123baa0e6754c5232202dbcdfadd0ee8d14dd19a7bea39781"),
        fr_hex("156195fe27df23b8184fc58a30e1a9bafcb9cc9fa9ce071163a26dccfb7c6ad0"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("20fed35942cbdc86df51a49ca26055bb25e232a42476ef06997af8911560fc12"),
        fr_hex("0cf20343957a55345423dd3450c2fd74039f1a82c6c02446dd64c4569d31471e"),
        fr_hex("1e177139b05dbe38a56c40f919dc1f07126bad03049fc4025d77b4bc34c25ebf"),
        fr_hex("144d1944a849fdc2aba8ab2a4368d57911e9614e3956d9326ca493c83050e932"),
        fr_hex("162f08d305fe4f1b0a9bb1acf1223bde3405aecbf2356508841b85f1180cbc1d"),
        fr_hex("21d68868502ab599c7c5f2a54d65be40ed5caec1613a98b2a98c5f8117415d97"),
        fr_hex("0984adb0c5263193be4027c68c6f3a6dbf7e22cf199dc4358b52968b0a248789"),
        fr_hex("2883f3a940a8c10f7f347a8011b0f0d7f6e0a4a82eff568fffc7524235d1e4f3"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("0d89a340993be3d3ba07d2fa8432d412730e8ebf2bbfacbf9378c0c4d3d1e692"),
        fr_hex("105e4a12836770bdbab24c85e7a63572c77556fffafc8f55a0e3f6e7383f7b02"),
        fr_hex("04b09e851bb6dbbffd0780af3f99cbb707f5e8a073810b28b1b59794c8b117a8"),
        fr_hex("2c8031907c10e1df2bfdd2589dd502a012a2292202e67954091ca57d21906d41"),
        fr_hex("088a360cf4c5e26faddcba291dd2553906abd82fecb0ffaff4f3f544f672d703"),
        fr_hex("0e9e8d8ba62712e7f95840b5651f32912e84f146bbd57c566c178084cbb155f8"),
        fr_hex("038fbaea7dd737c642ec414759bdeca4250d31d6011140e7e45e86c12c6f6fe2"),
        fr_hex("096dea6e0d6411dd0c18e516511b03d8506c4901c52dbc2772c3d47bdbf461ab"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("2d60fb66fb133b0507b6b41ed7fbd5278c4ba9fa0679d2889da9672d21f07037"),
        fr_hex("2567f444cfdbbf4d7799d5b50c8c582e1d2038a11969b3eb2b60aebafb1efc7b"),
        fr_hex("2401d941b4fafe3311bc6cd9fb0bef62ad9b59e731c1ec4e6b0ca5e2c685bb2c"),
        fr_hex("28747741579283853ed4e6525da70a4312769f7040db4f098eb7d9214fc8fae6"),
        fr_hex("1104899fde3f530cf99500f20c4fb9d479e512cd70a15def442a4ea92bcb9743"),
        fr_hex("04ddfde1b1aacb33977d4b3020db51b834f6197a18505e3ccfb37fa8a3a8764c"),
        fr_hex("2bfa6913d62c8aea04ccc3e50229220efe3b9af6a568194ece56c065e3cac8aa"),
        fr_hex("05cb914ec7b72436cf25adcbd0550c2db3c9c09aac565d46f96ac156fa72a90e"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("145dcc8a89ffd8fddf4e5bbe377a3b7649ab6faaddf5eb580ced3e0421b7077c"),
        fr_hex("21f1b7c169a0744e49718346cbd390dbe3287f5de3897acdaaf2e4bbc1f3e80b"),
        fr_hex("0eeae34b5e8e48d2ba6bd062c803ced1dd1165cce5f8f0574ff7caf4e6eaf6b4"),
        fr_hex("2827170c30a7f570a12f37aa0434e01a4aed9b5d37f1815029d5de89a8ff75e2"),
        fr_hex("0e328161a29c0376af526c8004597fbe018328d6d0c89503eaee36f59a4cee8a"),
        fr_hex("0d6617ff29ac941a779f907e749603cb36778fef6644b8684fa40055c8d978c6"),
        fr_hex("169506e0877092fdef32109c064d251c4d6a50257ab9c032bd79801fa23094ba"),
        fr_hex("08c516740479e1a852294e8cbbcbf83b4d7095b69758aaa9f1a368004dc1742a"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("281bcec4cbcefa9e18a1aca1dfeacd7f7ec527df5deb6c002f541ee4c0f2bcda"),
        fr_hex("13ea58a6a82bf43f6d4c2619b87da0ce760410b68b77f694685e3f34ff47b86c"),
        fr_hex("1ed604569bf581c71e4180d59a78dd48e2103006ac045566e44162656c36080b"),
        fr_hex("15d25d19f8fb93c9272f10ea525e787c758f98c5bca884e6317ed21a292abf6f"),
        fr_hex("1696701143abf5794f370a122fc60dafa4f0c241e8607983222bc72d1d8d1439"),
        fr_hex("1471c9bea5d880676ffb53255487c1af57a0476b77eba56204a4a3780b109b50"),
        fr_hex("1ec18e953909ee6e34dcbdde64fd6ae8b99817ffef4811551a27924b714cc00d"),
        fr_hex("089ad915c65eb1cc1633229dd97f098a2f86e7ea44ee6d94f3fe5f08682c807f"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("007e3bb22a5d8f517b12b42d68ab707d809ce83671dd9a933313d251889a9d55"),
        fr_hex("142b4285cb7ac7249975ddf59d177aeed1a94e0412002d83861ce061e3f38621"),
        fr_hex("24839c6f8fade0c2ef1e248f64c4d81e324caa4ef4052916a31c5d1da484ec43"),
        fr_hex("0ac0879ac864dc7bf40955a3f4a19cf37846fcfa9289ae59c8f8c7c174c5a57e"),
        fr_hex("044832eb1eb4ac43192406deb4a37ea61e2d110468762d3a31f01f3c6c1f8208"),
        fr_hex("2b3f948fb289860a26e995d14c6f8aba2089511c7ba58a310e6cbcb533f2dca2"),
        fr_hex("118bfa7e2d1386301f187c1b1eda2f48c0a03de15e370b5be0f431a0b574681e"),
        fr_hex("1399fb352bfce7874d22e0fcb24553b96ab59b85364c0c3c9b0135d4970c2349"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("2f25d0089300da1d286c5efcc9cf22d095af8f615b76cbee09b9ba651d737311"),
        fr_hex("084eaaf7a0b07cf4992c7d05790c42cc742a7bed021c48f614b988d99f141e3d"),
        fr_hex("0cbb53527ad34cbd3c4d59504fa47c87eb5be078155e58ac3f1e4b3f45dd1cec"),
        fr_hex("14e8e0d80d2af6efd3cc60741cbc21f6da3a42e2429322bc209097b1d22d26b4"),
        fr_hex("149dc605f3ad39d4b470a132191d2739df2ad19fb71e067f6ede3f9da3172922"),
        fr_hex("1533cdda4fe346f0a3e538172b8d5636d3b4b502047cb268015b2088f12b9897"),
        fr_hex("1da21ab47505b1ed4358160f3cd24a01330718bb901beedde8cca37839805c62"),
        fr_hex("130eee6229e6346096e121bda6bd3892aba85c363deda16ae8c8efc6ba721b18"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("1d0669bb3cb83ad8702a76855510918ef300df2416cdf04a83061a915a6fbdeb"),
        fr_hex("113f0f0db699267055417d499467b7502e23179a0c23787b7e8130967c95080d"),
        fr_hex("28cd66f5e2046799405a9c14282070ef66fd409507971fcbac16032499bada61"),
        fr_hex("230173d8146362d28c0cc9bc2c72a64afa7741b77653726017932821c1dc9502"),
        fr_hex("04b23de911f3a1d3f32366c35a7f293837e1e7e8287b8abde423b2b3ab81c187"),
        fr_hex("0d4bcdd5ff441637f977dba6d523ef1f6178ba245cda76e429a91b0ca994db04"),
        fr_hex("093bfbfaa8f3a8718603066321ce48219b55558f33e0f8645a93a41e6f4d3e2d"),
        fr_hex("24e21e25f0b3d0e754bfd0e91e62b5fcd232e756ab34cbed6b4ab709dfca551a"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("146990fff0e10b8d70a4411f57f9e74a03d2ac0127b216400b82c8c644038303"),
        fr_hex("1ddaefaba77bcd9c5ba0671b0a34a4cb37b7c689bdca187d90212f188ba4a87c"),
        fr_hex("0a7c37e8eab27e5edcfc3d6682b0267e3d9250fe470980956f5e3e5993ddaaaf"),
        fr_hex("2d81f6984b67d7cc74b35aa9d673878f05d517085812190798dd24a510b8d6b5"),
        fr_hex("07c46458e45e15ce1338bbe98ed3c0726664d8ae0c965bf0fc79ae31ad04a349"),
        fr_hex("16dd83567c7289d8ea0e62df8620df74f3c987d5f162b6b0a24ab09837b5d2da"),
        fr_hex("21819b9d78ef5e05c535a83e7d709f80f3ab5e8d733146139015ec4e34b29f1b"),
        fr_hex("2340a29e4e4d4e920f39a6a32149b54307f918a2e179e6c7288cd02834c0e44c"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("1ced784118aac9880c9fbbee28972453b36abc3d967b20e9b0a886af86d64305"),
        fr_hex("237848c6b0c87f794b30cad5a3cebfe2c6c9173f7a258f4ea139252338a3ea5a"),
        fr_hex("27c636aa956756d9ee04b355abe2fad8d703b1721fcf73b17a77751813c8abb4"),
        fr_hex("1b40358386698e21d43bd3950c00f81d6ae340eff9ac0821a213f8fabd142d09"),
        fr_hex("0695487b95b15feda7188ab9bd8072f0edfcdaea2dfbe06596f8c037bf52145b"),
        fr_hex("1df336831b6745c8f22a80c252ba12b24e2bb1e7fd3615cc96145d898dbf3220"),
        fr_hex("264b7a66fcd41995c19f021b71fcb1abd59986c55377a82ad92e79a1165e58f5"),
        fr_hex("208defb2122d53224aacda9868250ca3b39f78b13c9d150a14d75a886a1a42bc"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("1627fe11fe92ca5b0841cd804a211151ca6c0d2706b2a17ec17a7fd224a48a13"),
        fr_hex("0d483b82a1ed0d6788ec73c257cacba9738eae7232e365df112b15a93459627e"),
        fr_hex("24c490612a1636b43f902459851afb3cfc37d71db5e9ffd247116d5cbd34f9fc"),
        fr_hex("2f2d08c8cab748b056307066141837d5cf195104459a91084768548346c8593f"),
        fr_hex("042d3a4f87d782326b0c097a03de01ac1698954c8f300af708fa79a92e84790f"),
        fr_hex("2b064fb3fabe9deb1593d253ecc7a12fcfae3193e8f7e16ec563876f92e4c62c"),
        fr_hex("22b8060d8bd295c3a201655ef3891a481e21748554dcb7613ce6c0a532628e5a"),
        fr_hex("1526148f85ce610667aa96af20059f0b02c8a9d4d463b27f0711db72a545503a"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("12d2a42d255875bd671d376e499cd79393db48c414f967d53388f60b4e180986"),
        fr_hex("22d0f27c6767b64adf2eb09ed595e2f2c211a3504a8de66ac01991c81c0e2669"),
        fr_hex("1fbcdf3ca6f2e0739b571248a9a994ea913375db065ed255b5eca3fde587dc91"),
        fr_hex("0402b7640d18feac0c700cbea0d8f527a7c3fb44a110c4d7cff21deae9a70e40"),
        fr_hex("27f6c76f1b519e71c3888f1ece7cce4e0f99f231ddccc7798a31b0dee0c68206"),
        fr_hex("2fe908cd208699c9d8e3b0c09f5c0fd58716d0eb50017aa7d12df08b53d963ff"),
        fr_hex("1922a59ac83c1e2821afccf1610aa5fb0b3cf8eb3fe3f4957bac604c177fcffc"),
        fr_hex("126fc5609db3cb254a05919034b8a7f9a0f85ec5abbde6f85068607250ea0ac0"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("28db35e17bb31e5be954d69f5bf8f6838651bb6f5c80f750b6b7017643b6c28c"),
        fr_hex("26dd684288015065728c5e09454535a33e1537761d874102bd4ecd2baf40b384"),
        fr_hex("1895d33a312becc17090e45df74981b4fc4b220d3aaa346c7e8485311cab159d"),
        fr_hex("28bff25eb0f2a5c6d007a92a7c4d88bd9c12c5622d0ecc5a509c404048b7b5aa"),
        fr_hex("130136f07c7e09acd49556f3a6bf0739c9efc0a1be738453af67b31e845c976e"),
        fr_hex("259c455761e6b6420dadf3d6b64eb65493f989fb3e5698e7307a6d6075714ede"),
        fr_hex("1c9ac464fb08828d02006c7529eb1e8f45eef54405ed2cfaa133bd697f618929"),
        fr_hex("060abe65207efd0fda7b24719d35018f7607dd732e71c05077148f3d046dd180"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("2a41f347b5f6eebe8969667071926905a3e6e521b85a89006ec2f500ef42b000"),
        fr_hex("17840fa3a180177731bce340ffeb5a3b6a68b94e3f870501e787edc5a94db63b"),
        fr_hex("161ec94c3f624f928eadb0e2f2cf6b16430fba680a5a50590d89005a688d9b18"),
        fr_hex("22d8be171b4571fb5b773c3a548fbb286b06e2701ce99b7630866e1bca6e2cc5"),
        fr_hex("052464c9c7ad14525380aaea9b06e76f03db8edd220f90b03a9feef2fecfb978"),
        fr_hex("0bdee83b20d91ff9a0404d8b0593879c90f7be5a95a22c8e1b157d92c3cf4746"),
        fr_hex("2d84235b4f4e04262d8f246123b8e631ad51a4e1051f41f1c89cc42b61717302"),
        fr_hex("03d6b62f816bc4b464e2971cc6a7c1a585e519266c4627b1367ce7963cf93d86"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("16caff6fcc165168b3ed958d3aac8d09f98f670bdbb847ec0e9083a022d27692"),
        fr_hex("2cd4beaac59c5306bf76ef7e06c81adff6de4bee730cd4676e966db45fc067d4"),
        fr_hex("1b11abd8ee736830ffeda3782fc7a82623ecc5afa92c0ec9eeec58177ce8608b"),
        fr_hex("2c80d3430e64bf850c9e10a22f6b781fd513af20d4705435bc870ec8cbe93cee"),
        fr_hex("2d2f20d2ec0e52eec9fc2d0e49fef7a2454aa77a5055ebfc4d4449e8f83bd015"),
        fr_hex("1e51c55a8d7a04be4edae4f7dfe6137e96370ee2a4ed459ec524b19de646e0b0"),
        fr_hex("13d4327afa809e26c8f97e36ebb5be1d3992ec72d459760bbd25659790738f43"),
        fr_hex("176222f47d8c0ff9e8a967920376793dbdb9dcc3a79b44fd25e1f43a755e6b81"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("05193cbcb59713c78012ede93db828e69336a197fdd30c6b7d03b1cfcdd6adfc"),
        fr_hex("2bbe660fd34f6ac3f2545cba9f717d2eae9f8c60242851657f8661504a457c69"),
        fr_hex("1fe59c3d2724f4158483406e6cd62aafa121c451f13e48ab3c857b2293333c3b"),
        fr_hex("249c893f9de208601de45c9769ebad071eb864524003add0bde31fef7f4f91a7"),
        fr_hex("0c20c4a12bbd772e0dbb929b69b24751da26b0fa8639005ff786a25ac1a5fe96"),
        fr_hex("1a0750fb1d27bcb326ceb3a3065a487cf7d513d8954f31dfb174fc5ed95ce55b"),
        fr_hex("16d40c0ba7a7aa232eea997d45ec4f0567fb6814677b262aadfaefc91d409cad"),
        fr_hex("025ccf860fc7237cc8721aaf1c717190db40ccd65bf65d108b16f851cebca736"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("1a25b1a6b81926e968ffffa63979c900c1e82452c986ae599ef991ba214e6f67"),
        fr_hex("2b344bbb50400ea76151bd0b68c3139955f101c701d32befddcfec1ca72df25e"),
        fr_hex("1044e69af594eca5f9ca7ee28cc38d161d01037fe223412e2f10838bb9ffd1e5"),
        fr_hex("1145f6f783af7d1e0ee3388f107ccc27609bb8314bce27b03dbf8d02843ab2c7"),
        fr_hex("20ed7009a6093b160020318b0bbfbc9a9d14de64a3aa25936ddff0ffe3a3bc4b"),
        fr_hex("24cc5ed4ff9d84fce95c1508e1c7852fe60a6def592f423bb79c229327be7627"),
        fr_hex("1fc31b0e67cdf9efa9c0c312afe54b5158ada1511719c76953587b772f1c830c"),
        fr_hex("1faf997032cbbadc0c6d30fc804d068faeccbdf7cc90155395b739e017081259"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("1197c402e5f0a49c8f9b9a41af6fbcd013cf9adfe864613c1bdecb6201d9651e"),
        fr_hex("03025d698462f4cf23c7d4d8a3eec4aa8e1a2184a43020122db653afc6d0deb4"),
        fr_hex("0ecd1d402fafa3602052ab586f804ec15f1910542f35c608eb7a247d5a960cc9"),
        fr_hex("30021619d0c0b402b429d4e962cc3c2a2d00c62c131144f7b3d7f8acae6975b8"),
        fr_hex("2bcd05e889bf0fcd9dc4f5faf21c506cde15c316aaca47724e71bad0cf34b27d"),
        fr_hex("1b890b4097a781900b40d9c1ffa06a5e8cd05ae8fe52e040db0e7085ca46b460"),
        fr_hex("08081b53a974ee264310b279468093218cd5e5edec1b7da6b21ab35622242e48"),
        fr_hex("00e6632e8ec976cefca5b164e6c07ab40ac611fc723e8d8a14899a4cf4be3b2a"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("063a3f8dea9d024a6f6a851ecdb21bffbfe259ac17f6793c91e73823a82f4f76"),
        fr_hex("23b2c6ec9af5d0188e75baab9990f663f8e929bcdac96cc09c4c0626274692a0"),
        fr_hex("09a41c06730fe53d395c602113f1607fbe01425190d50d56e9f215658ad128cc"),
        fr_hex("16571048fa92024a9345a0ffecc159e76602455a71bc7e9c9c01dc50d8aa1d6c"),
        fr_hex("2a5a7e76dc76ad78878b3d3b4c74995e2ce77bc126e4d17db507161b049eadf6"),
        fr_hex("0a23738e129c11b285d81c1c01e3f87989c87600727e7593af45607f98fb18eb"),
        fr_hex("2ce8d6eeaf4d6c7ca0922c4738e81dfba227e98fc3ed24e7696ebe9c2732a1ff"),
        fr_hex("022e3bfb13d10368cee5175f5e2a2cc205d28021caf5fb2898de2389123178a5"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("066c43e71903c5b74ee8e90ec30a1d8cbff7d8c85d3c7b995a976036eef8c4b7"),
        fr_hex("2fe5dfcdc9335f0c0dd3d08f4e783a5ff6c2e6fb7e2928840821e6da8d91570a"),
        fr_hex("009accce03257f967a24c11ce718f21167d9d71a1cb60a4f50d0228418428300"),
        fr_hex("224e2a85316b67bf2dc64549c505721a7858438a00e793fe76b961bfbfb67291"),
        fr_hex("29f1447b45128f5c1cdb12a334509e0a991c0d2c9360a5cfc28af420c2ffffe0"),
        fr_hex("1301ae5665bd3e87cb647f566ebcf2f2eb5bec4b257a77061a15dcc7b8b34abf"),
        fr_hex("0fc6599ea957e02f69b1ca585c7135425a6825867d0cdd2b06019f3c9398ba4f"),
        fr_hex("022e91a30a945b960bd87d7b0d8290dcd5f5b1caa339c41aef323be1ba9c724e"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("1c7c359c26eab655aa469e0f9a8cc3d8c7a8149ba9e9baeca9233b7edddd1d24"),
        fr_hex("1ddf651a5d396b680828eaea1f252625db1988504765eb4aeae3274a19cef175"),
        fr_hex("0ab486e3e737f40898d3fdd6bab09213c0056c2e090a90acc754574739159385"),
        fr_hex("0d0b817b8995913e3ddd08b576951bd47b45f536739fc9cc782e769fd17e0028"),
        fr_hex("13471abd3a25160947928376fcd79dd5aa58672f8382745e3a040c2acb464974"),
        fr_hex("07bff672e50ff1f20296b1838e5270229a7477110d9a7fb56580371ee4ba38c4"),
        fr_hex("23f91ef1b8182e80c8a0f54c3a35ad51cb9a3bb61b07b3e34386f16f7f4b32bd"),
        fr_hex("16c390b3fdf09c6c42e50b66557532cc5998cb5a8c15446d31813e7b70607ec5"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("1976d21aee74f79c60d44e46029a5b04fc03ebfb9bdb09a0b5dbb89f677cd296"),
        fr_hex("056e7cdc08bff8d8bc12dc72af3c84858dde68919cd991bdf513656eb0a0cfb2"),
        fr_hex("22b7992d7c0ed349aab7531de2f12da4fdcf961215ba06f2b7577f5d42bfa85e"),
        fr_hex("10f97fcc757a0d6d0d4e2d585ea5968b3faba9d6458d16bd366d081ab65ae95a"),
        fr_hex("21bc046c3d727baf6e65b568653a398aeed8c95b73567feca3884a051ac001a2"),
        fr_hex("0e757fd0b77219a771723e071c9896062eedbb3da05cda25d39ead3cdf738491"),
        fr_hex("1ed536c497ff36f612f326f3d03e97d30abf91605ba686af36ea04c19cce4f4a"),
        fr_hex("2491340ecfed3f98ed6fd566034240e64a08e5a39a468c78b31e4734a679bd67"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("144b73c6f361a4c232674a08616b36c33f7bd667dcaeec35530a2e8fcb66103f"),
        fr_hex("00b244143540a248840ba5fa161cbfb2fb2dab97332073042cbf8a932144d27b"),
        fr_hex("0b5bedd8122560caf5a9dbd69f82f7439543bbad397d7cfb4ef7782f64ea4e12"),
        fr_hex("1386c7e88c5c0bf880b28eb2735e221c2a88e7f871ca5d720c99b4287c528a67"),
        fr_hex("277164cdc5187613b0a6d6450b56cabfc828f20dd7d07611edccbfc3d381c9ba"),
        fr_hex("016bc97ee1ac4b1cea8f96e731dfa610212aec4a193015b94b0f2a1657d41f13"),
        fr_hex("0b341e4361f31734af9951c20a6aace08a3dc80f57379add9693b56b047b3480"),
        fr_hex("263a060ba49fe4862df997994261e665c0406642c669c32dee4ae7a153fe1dbf"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("0df811b70cab32c0ad0aacb576fd95b23424d3686d79e36feeff21d1aa047eb8"),
        fr_hex("00afae979e41c0cf7d662b4cf09e93dca70c0945c6759c4f8d2c935a6084eced"),
        fr_hex("21ae12f1dbb152c33213efe9cdb6044574b3df8236be92341131435152115e5f"),
        fr_hex("272fd8955a7524a09f77c28ce89d58caf7d883f9e4503ad6a37c0eab6bcbe468"),
        fr_hex("03712cabfab0f6f3d23ac7beb815226883f409d60d798242c6d5e9dae8178fa6"),
        fr_hex("15bc41d746b14885ba93dc7d00594ea2f174b3b3dbc1acd774335405c18b154f"),
        fr_hex("09dded6d75c33754be1c1ebd2dbed077c1f1cb80938f0798bb2e25b054a52962"),
        fr_hex("1d9fd7f273e141e48d7ae825a6d7758e351d80c4ed50139a659d52edff60d227"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("00ca2cbfed626671d6e0f2e3d1b6b2ebb5e9048c2f1273223c34fe599429e1f2"),
        fr_hex("1e9bb2efac004014858166710da5d764ab36b80e4e97500d784fe5cc2326fca1"),
        fr_hex("23f8af81b77d2f06d566eb0d9096c4b267f498f92bac69d622dbed85bc8a8ada"),
        fr_hex("11546811642965c71b3865d830809b7f402e02d1980c3219c4bbe48e8bd37811"),
        fr_hex("2b872c434320ac521ac1e14867c05d88692de6ee063f402c28cba02adeaf9c51"),
        fr_hex("1f80e8d09a04ffb20613cd83ea35fc1593f9a5d8db6c846d80dca53cd4ba5a94"),
        fr_hex("117c4e17071565b51a2b97908f375ca0194dd595e9e873e8c0a158b59684ac70"),
        fr_hex("14da94b9be3adb3c5f7cd04dd5c58f63e74245d5a1e6fce5de3d093d476f08a4"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("2ac96264771dd5b1762078d5132db23febb0d2edb19c7b24848d4b654e9ce670"),
        fr_hex("05a23e8be5fe8e01b11d0c7a1dc85c909602604b15d620c7a51e2b017dd63830"),
        fr_hex("172623676d3d38b2c68ba2b30c12c5818d874d83a98478cbec0b1d27f5dd7ece"),
        fr_hex("0b632ee1e8730d509691580805b890371ca2d51bce083faed1615a845481de7b"),
        fr_hex("2a220ef566e4d54373e1a095231c10905a2f5e72edd2b6259b46ea45749203ce"),
        fr_hex("2ebf4340ee05460d8298d52260b4ebae389357bd857cb638c41b2708cc333dc8"),
        fr_hex("27e873b1750916366d2e7906ffe4f42e6dd7545bf534adc73a02b7410f7f8275"),
        fr_hex("1ee70cb51ad6da4513ce42ff200e46dfa39992a90447f1004765711f3f5ad52e"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("1021282efc84669e4a98956e30ad0043c6c19dfeb98d6d14bf027bcfa555f8af"),
        fr_hex("1f1c2e424bdeadd277162d70faeb398d661225414a975a59be613e47274b73c3"),
        fr_hex("1a71e415abc5ccd5bf268130070e89b1e61981cd54f6e5864b8cc4e1d50bb21b"),
        fr_hex("29799820e28bb9c0a7bd0a2c6d6105e5c91f8f88b2823da7c57825067214dbb6"),
        fr_hex("017377cb0195b95b473606c81a6bd5c807b22870afa6cb230a1048e9515e31db"),
        fr_hex("2f73cf9f22e0431d5e7bbd907ebeb8553b4117ff1fc50d09fc7b75935ef41251"),
        fr_hex("19cd57e77a99328260bd31fb993e7bb3fd27fdc21b2187fe3a4bac0ad664719c"),
        fr_hex("0d5ff1b6b5f33d6d568d9197d0df40d07abede20ae3a94a0292c01c304012713"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("26c7615e04be2355af0773fc0e025f86baab5f59d834ba005e099d95331d61b0"),
        fr_hex("170ea6732c6d1b2ce3279f2d4990926fb8d279e4864d966ce6ee6c319739c2f5"),
        fr_hex("2f870269a506f351fb0b9a9d677bad1bbc5e6ab40ff0afc1772f02ba395fdc8c"),
        fr_hex("11986790a1cc239c92bd4b8d8a1b9baa76e1e49f847f16ede5f6398aa83e97c2"),
        fr_hex("2510c2e5a39cd6c243ff590621941b221d2a2c5a79ed6e5bb90eb1008219239f"),
        fr_hex("1ba5c05a828609b93a7e151338699af0b8b0aa96d3d5cc9e7d3785333fa03dcd"),
        fr_hex("08648c03bd03b5f4dc3868ac1c47363d90010b9cb19933554fc7586b97b5fbda"),
        fr_hex("0069d0c72c5880618f66ad58d65f09e5fc488697c71d92135be291f55d496cb7"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("091acb34aa0d03afd0ea47c1d56965a9051b05eebff9af71e07c4554184f462a"),
        fr_hex("2b3f75e8ca7118776d9676fe058565eb99b6e99bd23505a8fefc927e17cf5336"),
        fr_hex("16d9ae82c0073fe1dcf35384c0dce87494b2400f9027ce1e64ee440a439fcbaa"),
        fr_hex("2a11becd9333eb48f3027ad8f3c24fa1a0ea671a1020278ad84c863c322e8057"),
        fr_hex("0d569be295d5e44ccffd9d3ba84aaf6a0c178e8639689aa6c57214f00a6a9d90"),
        fr_hex("0a66025e45040fd45eb136eccc63e2d7fd237aae9b62e2330aaaa0bb44dbef48"),
        fr_hex("2cda68234c7e22d8fd725d952d3c529b6997b68dc02065f6a047b6cabdd29e42"),
        fr_hex("1f9ab3e8029afc72f56af02ced5a6b145ebc81444ed12e82c7ea547e9ad23650"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("18a2e32bb69277e0f5e82c2a60a008b3db5caf3c53a669215c0b3493b73c7138"),
        fr_hex("224c4f2e98b4fa10d4ddc83f26ada461e5b4f412f94a1eb153be707470746fbf"),
        fr_hex("1b2a8787e954d981add1b123a6f6c100a609e8135c0781ac9a1e7e326c4b0f4e"),
        fr_hex("2da288c34f32d86d5dfc0b2dc9891091d396d36de9f70589b7beee769a058622"),
        fr_hex("2e24d351b0d0e94f3e0f83eb60f2d476b8b64dcb47674290e87b27eda7f20180"),
        fr_hex("14af016f9da2f982e82aec1ff6ee809445db2c6d85382f959508a31830dce9d7"),
        fr_hex("091aeac9bde9ce64a54cbad523032180c2135b51ec4547ebcda08824bc9cdf9e"),
        fr_hex("0caa07eac62d9f07c17f63f749b7047eaa1adda97f5716d76f23affd6d845dd3"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("0554f06e31b164d9d7ada3e01c4bbf452fdccac121ca787b08ad50dd2928ed42"),
        fr_hex("0bf8f8d7702b1e8830bf126dc420158a624359067a0f6385068390b01d176601"),
        fr_hex("1604d181baf488dce4f99bf63c065ed934ee29f0649af4dcc9ac2a2887e8690c"),
        fr_hex("0ac951e2944f7532d4ddce72d31c8e91c0795cdfab82df338f172dd9bffdae43"),
        fr_hex("24d53d9f665348c12bdc3425c2b83e24fbea3b66b0c9d119146ed5d5a1d1e9f3"),
        fr_hex("1ee01a89a7ebc6b8e93f2ac2e60b9909e3e3d855852e0e113a72a118f56e2da3"),
        fr_hex("2b78c3171a3c8ec6231bb7c208e5b7c2c90a85956a7f2a1f763cb6c883059938"),
        fr_hex("07ca1e306d90787461696fc7e4a3938712312494329be76c8e2b402cc0d617e1"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("1febc25f88aab92179ac3cefeea663f51562f6fc631bb236c04f5ef85b464784"),
        fr_hex("1b1b065eb60dbd39a34da94414fdfa4415933a6bdba5c2de470ad8ccef1b28fd"),
        fr_hex("0060fcebd24cc08503ac4f80c0ffb87d0898f34bdce41420e84d941b5f7d352a"),
        fr_hex("2a7b16d282447357a66d83fc5aafab7d3edbcb3f01105f193954c5ed496ae165"),
        fr_hex("0ac39f59e76b9e296ef53921ae0436ab01217493f948bf6eca12b11ce46678b5"),
        fr_hex("090b38aaae1df1873784a8966f1f62b68bbd93d34b0f4c637e208f9aeaedfc26"),
        fr_hex("1ba601baf813cb2d40ed5674747b9e3d5760143501e0f21e31a7dd44b7135eb8"),
        fr_hex("17695ec6204f10059ae5ca72c1332bc882cb7b4e161accd1ba9ef760b7365d5d"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("00ab5930a06bb6b9a78e664dc5308da0b64d1e09e6c69fa583bc737245c5a469"),
        fr_hex("16ab9a5de48bf089fba600dc70d2790ce0e8f79c1430566802f97fee43bc4e2b"),
        fr_hex("075df7d5cdb7ccc175462dfad73927bf5a5f465e15ad267930c5ec846f42ae5e"),
        fr_hex("23e4a7be74d0f0930279585aeaa432b5c28a4a2b21e3990aa45b5092f08d48ed"),
        fr_hex("298795a8af97b8b3d378279e60b276b95227e66d74e2dc66cffa1c495af98c25"),
        fr_hex("133d1455b6ea278f4acd91c65906bf75f2c90e41cdbefc2721b1e96adc5eeda7"),
        fr_hex("24b722af1967cddac6a1745b71aca7bac72d436ed464e2b8ce55aa2ad5ff3502"),
        fr_hex("276cb6e59cf4a06ff6775a537a4b04c6b42780c9c98a51ff634804b23acfac2b"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("1044b0ed6b39096c0ff4d292c18632c909d1519149139b1cd192de01485dce3e"),
        fr_hex("2dc918abffffceeb34cb17a8cb532f889d7dea98e9ad2686ef8e30936ecdb03a"),
        fr_hex("2a5030937ec5690d090ad8b3d897541ecd187d2ee126fac5be6a280fbd4aa465"),
        fr_hex("016961c105f85925010e0fdd445ee840dbd3370aab933ccfcb6e4b24a8826037"),
        fr_hex("17262da0f8e41b6c42707dfbabec1d9f79ecdfdd25a32c2a640d3c5a4a3e8770"),
        fr_hex("059935903a135cffc7c5e8cb06de7a0adbc6fe4f66b07a74172eb65951c6a345"),
        fr_hex("1ea2228bc5f09dadfabf025e3d19db3cca4e448e60f2973605d2559a27b3bff8"),
        fr_hex("1e35c4737f19de2debd3760ddc81e1f5857a01c42c86f4e264ba323f4165d5ed"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("05958875cfb17091058a7e29cbfe20d0d242ecdfbd3635279cd1e0c3a1144dd8"),
        fr_hex("19fd165b2741329dc18d2a5b03d7b58eb3dcdf2c2b0870731a924387139033dd"),
        fr_hex("11cea375386801203c61577504cdc68493716d023d116356def9ad9825be5887"),
        fr_hex("2e911408231ad83ab40e44e28ee0b017a82f7e080a0d4bc1b42c52e9205ed13a"),
        fr_hex("09d3f08c1d2cd4de393b703a7dd94df0540c91b59b288df6c1ad8ba0e51f179a"),
        fr_hex("0d8bac92c12807a3fb4b20ec11e083a88b953070c08c1ae9be28c80cddb29a50"),
        fr_hex("22829b774491c0e3add8e7d2de8096cb55a1009ae9ce983b80c14972bc68b84e"),
        fr_hex("2aec91a87a1731f6b2f534955aef3d09ca7e2ee2dbdb5e9a0d15db232557c621"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("281ec503552e6778fbafd7270951cfef153fcfeca0517410e495c62b81655f9e"),
        fr_hex("098a3183f2ee18973943856c28e0dceb4392af147ca8b528ebee97577178bcf1"),
        fr_hex("0794a78e51b51af07808b643ed37bad31e6d6c68e5ef3171dcd06de598c6c29e"),
        fr_hex("214a19348cd7cc8b1f985287e637e7987a3bedfa233f98dae9774daaea42fce9"),
        fr_hex("130acc584954a9048597bda6395bd25ba02fce56102928cea7d5a6f520683ca4"),
        fr_hex("01d09e1227434a4bcf72d8e91f5419ffd6da212a1d1ccb2a51b03e80aa258243"),
        fr_hex("127397f2b156ba00d83847f03dd242007faf326271d0e2cd4f6dc84c961b19a6"),
        fr_hex("0971a3d373d35db8f181e0d7b26c33cff17e533e8f560d844694f853e7197e47"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("241c8bcc463ac96e3c1cc240ce83c44edcf9c781e258a2dad09d1976d9dc6dd6"),
        fr_hex("1a0b489baf0a182599f458897aa340e57986dcde7bfd34738851092a75ae6e0e"),
        fr_hex("102c886ce6381276fe52d15c51dbd571e94904a8ec4d4445d457d596442e443e"),
        fr_hex("289f8a46d6792691caac00cd43dde74940f122c0e5ac202588349c2eee473f6b"),
        fr_hex("2ed1721123242c33f23f809f6e431511594c10b0533afde3304ba62afc55f5ec"),
        fr_hex("0c730a9beb7b64f090a39929af4901900e772b0f817098adace287cc20dd9e84"),
        fr_hex("0480eb2f48521f46f5049f8d9d682d6f4060ff6c4190b2a22c40c27d0754b912"),
        fr_hex("221d30bbccbb39bc23ffe2c8571a8cd1763cd48de6dfe21d7d8f2805db1e5066"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("022eff0bad54cf4f8fda9e07bfdae36713527756cff255aa481b730bd286cc90"),
        fr_hex("220c6f4c23ec9272eafb522055494a1af4de6fe7456b39c5db851e1299b7a86e"),
        fr_hex("18d66b43fd01a9cc88dd14b1b5d6c0d23b29ac28775ff60d3ccf36039de0963a"),
        fr_hex("1f62901537c1c56f671fabbb4fc31fa743f3236c26f9f5c98ecbf332eda817df"),
        fr_hex("130beece629451200a3de22eab4c45bb592aad667f9fc6729842971d4a802fcc"),
        fr_hex("24411acb2c9c481c59adc41bc54fdb0fac658ed6e0b3636cdadfd12c386f8c98"),
        fr_hex("2370059923938a3552819155a8b3816fb90cbde45871f6c122c190a27e7fdc43"),
        fr_hex("217ccb823582bf7edbf4a6a64692e37928f2b02d79b43775abf304500dd2da46"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("0e2be5d3f9ee73557a1c421fe42cb29bdf8f4a58679a61496bf8a5a4f9bba3be"),
        fr_hex("27639d7e461732f3baeb172103de2bc4a26708623919783fe54774153bdb59bf"),
        fr_hex("159c005b660c7fb3551cbf624aadcec047ce72625673c866c5fb289f8c865fff"),
        fr_hex("130d38734b549e833b50c550a90580c53248bb96731c0921ad6373316dfdaa8c"),
        fr_hex("13ee4afd14334602b6791a7b8f49c4f4979d485b8d1b1119cb4a2a7c31a74f39"),
        fr_hex("2d2647b74c63579e81a6270afc73e636e588996745ac0499dbeb6a7cf80a889e"),
        fr_hex("1b884086fa3c4173be0fd5cb1c866c87e0f9ae4c3d9f1e3df630cb4c2fa59af5"),
        fr_hex("2289328b5db5b2b2d00e76ff78815696e77eb19acdcb6c84279e65fcce29d15d"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("0bbd293300c70f612c8f5b7bcc6c4106246d2f713df02774a29742c31efeb4ae"),
        fr_hex("278e2893fbb5d590fe623652e50086d58ab18d3015a59d6a61602b409252ec2b"),
        fr_hex("2fcc41f73df0c835b0b514cbdd469af1e2b494f05269d15a6343af34668b18c9"),
        fr_hex("0378097f57525674b961d42a2f57a937c1fecaba4c673bdce345050d981b8fe0"),
        fr_hex("15a6727e6f181a5da795ce173f1889e07f12892e13f889c4f8f6c71725ab9f62"),
        fr_hex("1edc3a58673d364ba5906c3b39ff7f654c5d42f4ff94e6e75d2c500842846477"),
        fr_hex("01aeddbe743c87ec10fe447a5d08ab5c73836eb214ef95a08ce91131b8e1a7f8"),
        fr_hex("286e544456f114ce609d6b805b31064ab65482585699c91b9b3e83a75ca386b3"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("1477e88daf9348ea5f95cb08426f4285c654a897a2c4895333052fe2cdba34cb"),
        fr_hex("0c9918bbd089bc26c937ae2e0a92a1d8c87cf4480b055e43831a5e6a3acbe5b5"),
        fr_hex("283c24f7bedf789f31465682347ff86b4c0fbb7f9aacbe5630021b41532f7931"),
        fr_hex("0b1e5f0ca68bafaf026438a4682a55c1df5d387c4c5f3e111ead3163eb5b2754"),
        fr_hex("2d9da1df21f14ce401ff84b99fba07311a9da3cd7efc200695ab55b1233b9043"),
        fr_hex("0bb61e50ddc0821f0c03b3bed9476f580a02157b6a69a17f2afb0eff5f1e2a37"),
        fr_hex("21dc1358f62ff3dc24cfc896fdfbae88b0074323dfc7b36d680edba89c470e4b"),
        fr_hex("0dc75868b6f7e6ec9c26221637eb789b9e4c2b892ce81b527c7da05627ec2dc8"),
        fr_hex("251e7fdf99591080080b0af133b9e4369f22e57ace3cd7f64fc6fdbcf38d7da1"),
        fr_hex("08606e28acd8b2ee4c23a757886d7e99e407d177a58fb31b410ead7fbe1ef272"),
        fr_hex("2f70d379513ce458231a8ee6b3029bcbbb4860ef48c104ddcffe65603d81592d"),
        fr_hex("15315ba38b9e4c7a64a0844985e7b45db39eaec4c63b490cecfb19f02e102669"),
        fr_hex("2a1529e4b1ca0cee97cde58af1536c4823f7e558bdc13f774e4ef3ec8454675b"),
        fr_hex("2a70b9f1d4bbccdbc03e17c1d1dcdb02052903dc6609ea6969f661b2eb74c839"),
        fr_hex("2f69a7198e1fbcc7dea43265306a37ed55b91bff652ad69aa4fa8478970d401d"),
        fr_hex("0c3f050a6bf5af151981e55e3e1a29a13c3ffa4550bd2514f1afd6c5f721f830"),
        fr_hex("2a20e3a4a0e57d92f97c9d6186c6c3ea7c5e55c20146259be2f78c2ccc2e3595"),
    ]
}

static RC: OnceLock<[Fr; 100]> = OnceLock::new();
static MDS: OnceLock<[[Fr; 5]; 5]> = OnceLock::new();
static PMDS: OnceLock<[[Fr; 5]; 5]> = OnceLock::new();
static SPARSE: OnceLock<[Fr; 540]> = OnceLock::new();

fn rc() -> &'static [Fr; 100] {
    RC.get_or_init(x5_5_rc)
}
fn mds() -> &'static [[Fr; 5]; 5] {
    MDS.get_or_init(x5_5_mds)
}
fn pmds() -> &'static [[Fr; 5]; 5] {
    PMDS.get_or_init(x5_5_presparse)
}
fn smds() -> &'static [Fr; 540] {
    SPARSE.get_or_init(x5_5_sparse)
}

/// Poseidon permutation for x5_5 (t=5, rf=8, rp=60).
/// Matches Noir's `permute(consts::x5_5_config(), state)` exactly.
fn permute_x5_5(state: &mut [Fr; 5]) {
    let r = rc();
    let m = mds();
    let pm = pmds();
    let sm = smds();
    const T: usize = 5;
    const RF: usize = 8;
    const RP: usize = 60;

    for i in 0..T {
        state[i] += r[i];
    }

    // First full rounds (rf/2 - 1)
    for rd in 0..(RF / 2 - 1) {
        for s in state.iter_mut() {
            *s = s.pow([ALPHA]);
        }
        for i in 0..T {
            state[i] += r[T * (rd + 1) + i];
        }
        let mut ns = [Fr::zero(); T];
        for i in 0..T {
            for j in 0..T {
                ns[i] += state[j] * m[j][i];
            }
        }
        *state = ns;
    }

    // Last full round of first half: S-box + ARK + presparse_mds
    for s in state.iter_mut() {
        *s = s.pow([ALPHA]);
    }
    for i in 0..T {
        state[i] += r[T * (RF / 2) + i];
    }
    {
        let mut ns = [Fr::zero(); T];
        for i in 0..T {
            for j in 0..T {
                ns[i] += state[j] * pm[j][i];
            }
        }
        *state = ns;
    }

    // Partial rounds
    for rd in 0..RP {
        state[0] = state[0].pow([ALPHA]);
        state[0] += r[(RF / 2 + 1) * T + rd];
        let sb = (T * 2 - 1) * rd;
        let mut ns0 = Fr::zero();
        for j in 0..T {
            ns0 += sm[sb + j] * state[j];
        }
        for k in 1..T {
            state[k] += state[0] * sm[sb + T + k - 1];
        }
        state[0] = ns0;
    }

    // Second full rounds (rf/2 - 1)
    for rd in 0..(RF / 2 - 1) {
        for s in state.iter_mut() {
            *s = s.pow([ALPHA]);
        }
        let ri = (RF / 2 + 1) * T + RP + rd * T;
        for i in 0..T {
            state[i] += r[ri + i];
        }
        let mut ns = [Fr::zero(); T];
        for i in 0..T {
            for j in 0..T {
                ns[i] += state[j] * m[j][i];
            }
        }
        *state = ns;
    }

    // Final round: S-box + MDS (no ARK)
    for s in state.iter_mut() {
        *s = s.pow([ALPHA]);
    }
    let mut ns = [Fr::zero(); T];
    for i in 0..T {
        for j in 0..T {
            ns[i] += state[j] * m[j][i];
        }
    }
    *state = ns;
}

/// Noir-compatible Poseidon sponge hash using x5_5 (rate=4, capacity=1).
/// Matches Noir's `poseidon::poseidon::bn254::sponge(msg)`.
pub fn sponge(inputs: &[Fr]) -> Fr {
    const RATE: usize = 4;
    const CAP: usize = 1;
    let mut state = [Fr::zero(); RATE + CAP];
    let mut i: usize = 0;
    for &input in inputs {
        state[CAP + i] += input;
        i += 1;
        if i == RATE {
            permute_x5_5(&mut state);
            i = 0;
        }
    }
    if i != 0 {
        permute_x5_5(&mut state);
    }
    state[CAP]
}

/// Legacy alias for backward compatibility.
pub fn poseidon_sponge_native_noir(inputs: &[Fr]) -> Fr {
    sponge(inputs)
}

/// Hash two field elements using Noir's `bn254::hash_2` (x5_3 permutation).
pub fn hash_2(left: Fr, right: Fr) -> Fr {
    hash_internal_dynamic(&[left, right], x5_3_dynamic())
}

/// Hash nine field elements using Noir's `bn254::hash_9` (x5_10 permutation).
pub fn hash_9(inputs: &[Fr; 9]) -> Fr {
    hash_internal_dynamic(inputs, x5_10_dynamic())
}

/// Hash arbitrary number of inputs.
pub fn hash_n(inputs: &[Fr]) -> Fr {
    sponge(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sponge_empty_is_zero() {
        assert!(sponge(&[]).is_zero());
    }

    #[test]
    fn test_sponge_single_input() {
        let a = Fr::from(1u64);
        let h = sponge(&[a]);
        assert!(!h.is_zero(), "sponge single input should not be zero");
    }

    #[test]
    fn test_sponge_two_inputs() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let h = sponge(&[a, b]);
        assert!(!h.is_zero());
    }

    #[test]
    fn test_sponge_consistency() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let c = Fr::from(3u64);
        let d = Fr::from(4u64);
        let h1 = sponge(&[a, b, c, d]);
        // Same inputs should give same hash
        let h2 = sponge(&[a, b, c, d]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_sponge_permutation_applied() {
        // With exactly rate inputs, permutation is applied
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let c = Fr::from(3u64);
        let d = Fr::from(4u64);
        let h = sponge(&[a, b, c, d]);
        // Different order gives different result
        let h2 = sponge(&[d, c, b, a]);
        assert_ne!(h, h2);
    }

    /// Cross-language test: 5 inputs trigger two permutations
    /// (rate=4 means first 2 pairs + 1 remainder)
    #[test]
    fn test_sponge_five_inputs() {
        let inputs: Vec<Fr> = (1..=5).map(|i| Fr::from(i as u64)).collect();
        let h = sponge(&inputs);
        assert!(!h.is_zero());
    }

    /// Cross-language test: 9 inputs (matching vector_hash pattern)
    #[test]
    fn test_sponge_nine_inputs() {
        let inputs: Vec<Fr> = (1..=9).map(|i| Fr::from(i as u64)).collect();
        let h = sponge(&inputs);
        assert!(!h.is_zero());
    }

    /// Noir's `hash_2` is a fixed-arity x5_3 hash, not the variable-length sponge.
    #[test]
    fn test_hash_2_differs_from_sponge() {
        let a = Fr::from(42u64);
        let b = Fr::from(99u64);
        assert_ne!(hash_2(a, b), sponge(&[a, b]));
    }

    // ── Cross-language hash agreement tests ──
    // These values are verified against Noir's poseidon::bn254::sponge.
    // If these fail, the Rust round constants or permutation logic differs from Noir.

    /// Cross-language: sponge([1, 2]) matches Noir.
    #[test]
    fn test_cross_lang_sponge_1_2() {
        let h = sponge(&[Fr::from(1u64), Fr::from(2u64)]);
        assert_eq!(
            h,
            fr_hex("2dddd542213b9228162ff1b438c3709c057a9550103c9173c6204fb29b802c37")
        );
    }

    /// Cross-language: sponge([42]) matches Noir.
    #[test]
    fn test_cross_lang_sponge_42() {
        let h = sponge(&[Fr::from(42u64)]);
        assert_eq!(
            h,
            fr_hex("13f3e672ad239ac1b07e621284c5c078a5319e9842df7222a180893243919052")
        );
    }

    /// Cross-language: sponge([1..9]) matches Noir.
    #[test]
    fn test_cross_lang_sponge_1_to_9() {
        let inputs: Vec<Fr> = (1..=9).map(|i| Fr::from(i as u64)).collect();
        let h = sponge(&inputs);
        assert_eq!(
            h,
            fr_hex("078586eb4ca134c5c200d58088da25a5aa55e142e077b7e1a46c701bade73627")
        );
    }

    /// Cross-language: sponge([0xdead, 0xbeef]) matches Noir.
    #[test]
    fn test_cross_lang_hash_pair() {
        let h = sponge(&[Fr::from(0xdeadu64), Fr::from(0xbeefu64)]);
        assert_eq!(
            h,
            fr_hex("1ded065fd7e20cba7b17138b4e886ff4d2a4024dc06bc4021412ac749d870006")
        );
    }

    /// Cross-language: Noir bn254::hash_2([1, 2]) uses x5_3 and returns permuted state[0].
    #[test]
    fn test_cross_lang_hash_2_1_2() {
        let h = hash_2(Fr::from(1u64), Fr::from(2u64));
        assert_eq!(
            h,
            fr_hex("115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a")
        );
    }

    /// Cross-language: Noir bn254::hash_9([1..9]) uses x5_10 and returns permuted state[0].
    #[test]
    fn test_cross_lang_hash_9_1_to_9() {
        let inputs = [
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
            Fr::from(5u64),
            Fr::from(6u64),
            Fr::from(7u64),
            Fr::from(8u64),
            Fr::from(9u64),
        ];
        let h = hash_9(&inputs);
        assert_eq!(
            h,
            fr_hex("1e0b893aa2ad802275e749d260330b7675b22bb3aaa4461d204af32e60cd9078")
        );
    }
}
