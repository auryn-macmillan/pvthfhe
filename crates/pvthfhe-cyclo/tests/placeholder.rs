//! Object-safety smoke test for CycloAdapter trait.
use pvthfhe_cyclo::CycloAdapter;

fn _assert_object_safe(_: &dyn CycloAdapter) {}
