fn main() {
    let example = pvthfhe_bench::worked_example::generate(42);
    println!("{}", pvthfhe_bench::worked_example::render_report(&example));
}
