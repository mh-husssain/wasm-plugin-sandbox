/// Runtime sandbox limits and capability allow-list policy.
#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    /// Maximum memory budget in bytes available to plugin execution.
    pub max_memory_bytes: u64,
    /// Maximum execution time budget in milliseconds.
    pub max_execution_ms: u64,
    /// Whether network egress capability is allowed.
    pub allow_network: bool,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self { max_memory_bytes: 128 * 1024 * 1024, max_execution_ms: 30_000, allow_network: false }
    }
}

impl SandboxPolicy {
    /// Returns whether a capability is permitted by this sandbox policy.
    ///
    /// # Arguments
    /// - `capability`: Capability identifier from plugin manifest.
    ///
    /// # Returns
    /// `true` when capability usage is allowed.
    pub fn allows_capability(&self, capability: &str) -> bool {
        if capability == "net.egress" {
            return self.allow_network;
        }

        true
    }

    /// Validates that numeric sandbox limits are non-zero.
    ///
    /// # Returns
    /// `true` when memory and timeout limits are both greater than zero.
    pub fn is_valid(&self) -> bool {
        self.max_memory_bytes > 0 && self.max_execution_ms > 0
    }
}
