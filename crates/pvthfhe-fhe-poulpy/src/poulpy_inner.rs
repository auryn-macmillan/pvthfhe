use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rand::rngs::StdRng;
use rand::SeedableRng;
use rand_core::RngCore as RngCoreV6;

use poulpy_core::layouts::{
    Base2K, Degree, Dnum, Dsize, GLWELayout, GLWETensorKeyLayout, Rank, TorusPrecision,
};
use poulpy_hal::api::ModuleNew;
use poulpy_hal::layouts::Module;

use pvthfhe_fhe::error::FheError;
use pvthfhe_fhe::Params;

use crate::Scheme;

pub struct PoulpyInner {
    pub(crate) scheme: Scheme,
    #[allow(dead_code)]
    pub(crate) ckks_module: Option<Module<poulpy_cpu_ref::NTT120Ref>>,
    pub(crate) ckks_glwe_layout: Option<GLWELayout>,
    pub(crate) ckks_tsk_layout: Option<GLWETensorKeyLayout>,
    #[allow(dead_code)]
    pub(crate) tfhe_module: Option<Module<poulpy_cpu_ref::NTT120Ref>>,
    pub(crate) secret_keys: Arc<Mutex<HashMap<u32, Vec<u8>>>>,
    pub(crate) tensor_keys: Arc<Mutex<HashMap<u32, Vec<u8>>>>,
    pub(crate) public_tensor_key: Arc<Mutex<Option<Vec<u8>>>>,
}

impl Clone for PoulpyInner {
    fn clone(&self) -> Self {
        Self {
            scheme: self.scheme,
            ckks_module: None,
            ckks_glwe_layout: self.ckks_glwe_layout,
            ckks_tsk_layout: self.ckks_tsk_layout,
            tfhe_module: None,
            secret_keys: self.secret_keys.clone(),
            tensor_keys: self.tensor_keys.clone(),
            public_tensor_key: self.public_tensor_key.clone(),
        }
    }
}

impl PoulpyInner {
    pub fn new(scheme: Scheme, params: &Params) -> Result<Self, FheError> {
        match scheme {
            Scheme::Ckks => {
                let n = params.n;
                if !n.is_power_of_two() || n < 512 {
                    return Err(FheError::InvalidParams {
                        reason: format!("CKKS requires N power of two >= 512, got {n}"),
                    });
                }

                let glwe_layout = GLWELayout {
                    n: Degree(n),
                    base2k: Base2K(52),
                    k: TorusPrecision(728),
                    rank: Rank(1),
                };

                let dsize = 1usize;
                let base2k = 52usize;
                let k = 728usize;
                let tsk_layout = GLWETensorKeyLayout {
                    n: Degree(n),
                    base2k: Base2K(base2k as u32),
                    k: TorusPrecision((k + dsize * base2k) as u32),
                    rank: Rank(1),
                    dsize: Dsize(dsize as u32),
                    dnum: Dnum(k.div_ceil(dsize * base2k) as u32),
                };

                let module = Module::<poulpy_cpu_ref::NTT120Ref>::new(n as u64);

                Ok(Self {
                    scheme,
                    ckks_module: Some(module),
                    ckks_glwe_layout: Some(glwe_layout),
                    ckks_tsk_layout: Some(tsk_layout),
                    tfhe_module: None,
                    secret_keys: Arc::new(Mutex::new(HashMap::new())),
                    tensor_keys: Arc::new(Mutex::new(HashMap::new())),
                    public_tensor_key: Arc::new(Mutex::new(None)),
                })
            }
            Scheme::Tfhe => {
                let module = Module::<poulpy_cpu_ref::NTT120Ref>::new(1);
                Ok(Self {
                    scheme,
                    ckks_module: None,
                    ckks_glwe_layout: None,
                    ckks_tsk_layout: None,
                    tfhe_module: Some(module),
                    secret_keys: Arc::new(Mutex::new(HashMap::new())),
                    tensor_keys: Arc::new(Mutex::new(HashMap::new())),
                    public_tensor_key: Arc::new(Mutex::new(None)),
                })
            }
        }
    }

    #[allow(dead_code)]
    pub fn rng_v10_from_v6(rng: &mut dyn RngCoreV6) -> StdRng {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        StdRng::from_seed(seed)
    }
}
