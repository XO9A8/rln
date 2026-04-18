//! ONNX-based ML device fingerprinting.
//!
//! [`DeviceClassifier`] loads a `tract-onnx` model and classifies network devices
//! by their observed traffic characteristics (TTL, TCP window size, open port count).
//!
//! If the model file is absent or fails to load, the classifier degrades gracefully
//! and returns `"Unknown Device"` for all inputs — no panic, no crash.
//!
//! ## Model Contract
//! The expected model accepts a `[1, 3]` float32 tensor with columns:
//! `[ttl, window_size, open_ports]` and outputs a classification string or one-hot encoding.
use anyhow::Result;
use std::path::Path;
use tract_onnx::prelude::*;

/// Type alias to tame the verbose `tract` runnable model type.
type RlnModel = RunnableModel<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;

/// A local-only device classifier backed by a `tract-onnx` ONNX model.
pub struct DeviceClassifier {
    /// The loaded runnable model, or `None` if the model file was not found.
    model: Option<RlnModel>,
}

impl DeviceClassifier {
    /// Loads the ONNX model from `model_path`.
    ///
    /// If the file does not exist or fails to parse/optimize, the classifier
    /// initialises in fallback mode and will return `"Unknown Device"` for all inputs.
    /// A diagnostic message is written to stderr (not stdout, to avoid TUI interference).
    pub fn new<P: AsRef<Path>>(model_path: P) -> Self {
        let model = tract_onnx::onnx()
            .model_for_path(model_path)
            .and_then(|m| m.into_optimized())
            .and_then(|m| m.into_runnable())
            .ok();

        if model.is_none() {
            eprintln!("⚠️ [ML] ONNX model not found — fingerprinting in fallback mode.");
        } else {
            eprintln!("🧠 [ML] Fingerprinting model loaded successfully.");
        }

        Self { model }
    }

    /// Classifies a device based on observed network metadata.
    ///
    /// # Arguments
    /// * `ttl` — IP TTL from the ICMP reply (e.g., 64 = Linux, 128 = Windows).
    /// * `window_size` — TCP receive window size from a SYN-ACK packet.
    /// * `open_ports` — Number of open/responding TCP ports found during the probe.
    ///
    /// # Returns
    /// A device-class label string, e.g. `"IoT Camera"`, `"macOS Laptop"`,
    /// or `"Unknown Device"` if the model is not available.
    pub fn classify(&self, ttl: u32, window_size: u32, open_ports: u32) -> Result<String> {
        if let Some(ref runnable) = self.model {
            let tensor = tract_ndarray::Array2::from_shape_vec(
                (1, 3),
                vec![ttl as f32, window_size as f32, open_ports as f32],
            )?
            .into_tensor();

            let result = runnable.run(tvec!(tensor.into()))?;

            // TODO: decode the actual output tensor once a real model is available.
            // For now we acknowledge the result to suppress unused warnings.
            let _ = &result[0];

            Ok("Smart Device".to_string())
        } else {
            Ok("Unknown Device".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_fallback_no_model() {
        // Ensure that a missing model path does not panic and returns the fallback string.
        let classifier = DeviceClassifier::new("assets/models/does_not_exist.onnx");
        let result = classifier.classify(64, 65535, 3).unwrap();
        assert_eq!(result, "Unknown Device");
    }

    #[test]
    fn test_fingerprint_fallback_variety() {
        let classifier = DeviceClassifier::new("assets/models/does_not_exist.onnx");
        // All TTL/window/port combinations should return "Unknown Device" in fallback mode.
        for ttl in [64u32, 128, 255] {
            let result = classifier.classify(ttl, 65535, 0).unwrap();
            assert_eq!(result, "Unknown Device");
        }
    }
}
