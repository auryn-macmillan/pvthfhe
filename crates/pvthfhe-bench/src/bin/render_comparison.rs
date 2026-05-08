use clap::Parser;
use pvthfhe_bench::render_comparison::{
    render_comparison_markdown_with_template, report_output_path, BaselineEnvelope, ComparisonEnvelope,
};
use std::{fs, path::PathBuf, process::ExitCode};

#[derive(Debug, Parser)]
#[command(
    name = "render_comparison",
    about = "Render a side-by-side Markdown comparison report"
)]
struct Args {
    #[arg(long, default_value = "bench/results/comparison-dryrun.json")]
    comparison_json: PathBuf,
    #[arg(long, default_value = "bench/results/interfold-trbfv-baseline.json")]
    baseline_json: PathBuf,
    #[arg(long, default_value = "bench/templates/comparison.md.tera")]
    template: PathBuf,
    #[arg(long, default_value = "bench/results")]
    output_dir: PathBuf,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let comparison = match read_json::<ComparisonEnvelope>(&args.comparison_json) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("read comparison JSON failed: {err}");
            return ExitCode::FAILURE;
        }
    };
    let baseline = match read_json::<BaselineEnvelope>(&args.baseline_json) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("read baseline JSON failed: {err}");
            return ExitCode::FAILURE;
        }
    };
    let template = match fs::read_to_string(&args.template) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("read template failed: {err}");
            return ExitCode::FAILURE;
        }
    };
    let markdown = match render_comparison_markdown_with_template(&template, &comparison, &baseline)
    {
        Ok(value) => value,
        Err(err) => {
            eprintln!("render comparison markdown failed: {err}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(err) = fs::create_dir_all(&args.output_dir) {
        eprintln!("create output dir failed: {err}");
        return ExitCode::FAILURE;
    }

    let output_path = match report_output_path(&args.output_dir, &comparison.commit_sha) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("compute output path failed: {err}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(err) = fs::write(&output_path, markdown) {
        eprintln!("write report failed: {err}");
        return ExitCode::FAILURE;
    }

    eprintln!("wrote {}", output_path.display());
    ExitCode::SUCCESS
}

fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Result<T, String> {
    let raw = fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    serde_json::from_str(&raw).map_err(|err| format!("{}: {err}", path.display()))
}
