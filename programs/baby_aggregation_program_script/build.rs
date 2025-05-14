fn main() {
    sp1_build::build_program_with_args(
        "../baby_aggregation_program",
        sp1_build::BuildArgs {
            warning_level: sp1_build::WarningLevel::Minimal,
            ..Default::default()
        },
    );
}
