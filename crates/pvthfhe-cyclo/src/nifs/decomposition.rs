use crate::{
    decompose,
    ring::{RqPoly},
};

pub fn decompose_witness(w: &[RqPoly], b_small: u64, k: usize) -> Vec<Vec<RqPoly>> {
    let n = w.len();
    let mut parts: Vec<Vec<RqPoly>> = (0..k).map(|_| Vec::with_capacity(n)).collect();

    for poly in w {
        let decomposed = decompose::decompose_rqpoly_base_B(poly, b_small, k);
        for (part, part_poly) in parts.iter_mut().zip(decomposed.into_iter()) {
            part.push(part_poly);
        }
    }

    parts
}

pub fn recompose_witness(w_parts: &[Vec<RqPoly>], b_small: u64) -> Vec<RqPoly> {
    if w_parts.is_empty() {
        return Vec::new();
    }
    let n = w_parts[0].len();
    let mut result = Vec::with_capacity(n);

    for j in 0..n {
        let polys: Vec<RqPoly> = w_parts.iter().map(|part| part[j].clone()).collect();
        result.push(decompose::recompose_rqpoly_base_B(&polys, b_small));
    }

    result
}
