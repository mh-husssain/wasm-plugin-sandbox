/// High-level intent used to classify requested analysis strategy.
#[derive(Debug, Clone, Default)]
pub enum AnalysisIntent {
    /// Static analysis mode.
    #[default]
    Static,
}
