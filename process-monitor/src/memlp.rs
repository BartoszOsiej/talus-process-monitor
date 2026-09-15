//! MeMLP — **M**odular **e**mbedded **M**ulti-**L**ayer **P**erceptron Model.
//!
//! The neural-network stack embedded directly in the Talus agent, built from
//! scratch — no `ndarray`, no `tch`, no ONNX runtime. A few KB of Rust that
//! runs 100% on the CPU inside the agent process.
//!
//! * **Modular** — one model file contains several specialist MLP modules,
//!   each solving a single detection task (ransomware classification,
//!   lateral-movement scoring, persistence detection). Modules share nothing
//!   but the checkpoint file.
//! * **Embedded** — the whole stack is dependency-free, serialises to JSON
//!   checkpoints between runs and trains online from live eBPF traffic.
//! * **Multi-layer** — every module is a true multi-layer perceptron with
//!   ReLU hidden layers, a softmax output and online gradient-descent
//!   training (backprop + cross-entropy loss).
//!
//! Architecture of the default model ([`MeMLP::new`]):
//!
//! | Module        | Shape             | Task                                    |
//! |---------------|-------------------|-----------------------------------------|
//! | `ransomware`  | 10 → 24 → 16 → 3  | benign / suspicious / ransomware        |
//! | `lateral`     | 10 → 12 → 2       | normal / lateral-movement suspect       |
//! | `persistence` | 10 → 12 → 2       | normal / persistence suspect            |
//!
//! Every module consumes the same 10-feature behavioural embedding built
//! from the live eBPF event stream (see [`PidFeatures`]) — different heads,
//! one shared view of the process, mirroring how the NV2.0 engine feeds one
//! climate embedding to all of its specialist heads.

use std::collections::HashSet;
use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// Version of the MeMLP checkpoint format.
pub const MEMLP_VERSION: u32 = 1;

/// Ransomware module shape: 10 behavioural features → 3 verdict classes.
pub const RANSOMWARE_ARCH: [usize; 4] = [10, 24, 16, 3];
/// Lateral-movement module shape: 10 features → 2 classes.
pub const LATERAL_ARCH: [usize; 3] = [10, 12, 2];
/// Persistence module shape: 10 features → 2 classes.
pub const PERSISTENCE_ARCH: [usize; 3] = [10, 12, 2];

/// Output classes of the `ransomware` module (index = [`RANSOMWARE_ARCH`] output dim).
pub const RANSOMWARE_CLASSES: usize = 3;

/* ================================================================ */
/*  Behavioural feature extraction                                   */
/* ================================================================ */

/// Sliding-window behavioural features for one PID.
///
/// The monitor feeds events in via `observe_*` and decays the window every
/// second (exponential half-life), so the embedding always reflects roughly
/// the last few seconds of activity — the same 1-second granularity as the
/// heuristic sliding window, but smoothed.
#[derive(Debug, Clone, Default)]
pub struct PidFeatures {
    opens: f64,
    execs: f64,
    net: f64,
    fs: f64,
    destructive: f64,
    suspicious_ext: f64,
    persistence_hits: f64,
    entropy_sum: f64,
    entropy_n: u64,
    exts: HashSet<String>,
    files: HashSet<String>,
}

/// File extensions treated as ransomware markers when a process opens many
/// of them in a short window. Deliberately conservative — `.bak` or `.zip`
/// are legitimate tools too and stay out of the list.
pub const RANSOMWARE_EXTS: &[&str] = &[
    "enc",
    "crypt",
    "locked",
    "encrypted",
    "ransom",
    "locky",
    "cerber",
    "wallet",
    "onion",
    "cryptolocker",
    "keepcalm",
    "restore",
];

/// Path fragments treated as autostart / persistence locations.
pub const PERSISTENCE_PATHS: &[&str] = &[
    "/etc/cron",
    "/etc/systemd",
    "/etc/init.d",
    "/etc/rc.local",
    "/.config/autostart",
    "/.bashrc",
    "/.profile",
    "/.ssh/authorized_keys",
    "/usr/lib/systemd",
    "/lib/systemd",
    "/etc/profile.d",
    "/etc/ld.so.preload",
];

impl PidFeatures {
    /// Record one file-open. `entropy` is the normalised Shannon entropy of
    /// the filename (0.0–1.0, as computed by the monitor).
    pub fn observe_open(&mut self, path: &str, extension: Option<&str>, entropy: f64) {
        self.opens += 1.0;
        self.entropy_sum += entropy.clamp(0.0, 1.0);
        self.entropy_n += 1;
        if self.files.len() < 256 {
            self.files.insert(path.to_string());
        }
        if let Some(ext) = extension {
            if !ext.is_empty() {
                if self.exts.len() < 32 {
                    self.exts.insert(ext.to_string());
                }
                if RANSOMWARE_EXTS.contains(&ext) {
                    self.suspicious_ext += 1.0;
                }
            }
        }
        if PERSISTENCE_PATHS.iter().any(|p| path.contains(p)) {
            self.persistence_hits += 1.0;
        }
    }

    /// Record one execve. `network` marks network syscalls (connect/accept/
    /// sendto/recvfrom), which the monitor counts alongside execs.
    pub fn observe_exec(&mut self, network: bool) {
        self.execs += 1.0;
        if network {
            self.net += 1.0;
        }
    }

    /// Record one filesystem-mutation event (mkdir/unlink/chmod).
    /// `destructive` marks unlink/chmod — the delete-and-rename half of a
    /// ransomware damage pattern.
    pub fn observe_fs(&mut self, destructive: bool) {
        self.fs += 1.0;
        if destructive {
            self.destructive += 1.0;
        }
    }

    /// Halve every counter (1-second half-life) and drop the per-second
    /// distinct-file/-extension sets. Called once per monitor tick.
    pub fn decay(&mut self) {
        self.opens *= 0.5;
        self.execs *= 0.5;
        self.net *= 0.5;
        self.fs *= 0.5;
        self.destructive *= 0.5;
        self.suspicious_ext *= 0.5;
        self.persistence_hits *= 0.5;
        self.entropy_sum *= 0.5;
        self.entropy_n = (self.entropy_n / 2).max(1);
        self.files.clear();
        self.exts.clear();
    }

    /// Whether this PID has generated enough signal to train on.
    /// Reserved for policy gating; exercised in unit tests.
    #[allow(dead_code)]
    pub fn is_trainable(&self) -> bool {
        self.opens >= 5.0
    }

    /// Whether this PID has any recent activity (map-retention criterion).
    pub fn has_activity(&self) -> bool {
        self.opens > 0.0 || self.execs > 0.0 || self.fs > 0.0
    }

    /// Build the 10-dimensional behavioural embedding (all values 0.0–1.0):
    ///
    /// | # | Feature                                        |
    /// |---|------------------------------------------------|
    /// | 0 | file-open rate (normalised to 100/s)           |
    /// | 1 | exec + network rate (normalised to 20/s)       |
    /// | 2 | mean filename Shannon entropy                  |
    /// | 3 | ransomware-marker extension fraction           |
    /// | 4 | extension diversity (normalised to 8)          |
    /// | 5 | filesystem-mutation rate (normalised to 50/s)  |
    /// | 6 | destructive fraction (unlink/chmod of fs ops)  |
    /// | 7 | distinct-file fraction (mass-encryption shape) |
    /// | 8 | persistence-path fraction                      |
    /// | 9 | network fraction of exec/net events            |
    pub fn features(&self) -> [f32; 10] {
        let opens = self.opens.max(1.0);
        let execs = self.execs.max(1.0);
        let fs = self.fs.max(1.0);
        let entropy_mean = if self.entropy_n > 0 {
            self.entropy_sum / self.entropy_n as f64
        } else {
            0.0
        };
        [
            (self.opens / 100.0).min(1.0) as f32,
            (self.execs / 20.0).min(1.0) as f32,
            entropy_mean as f32,
            (self.suspicious_ext / opens).min(1.0) as f32,
            (self.exts.len() as f64 / 8.0).min(1.0) as f32,
            (self.fs / 50.0).min(1.0) as f32,
            (self.destructive / fs).min(1.0) as f32,
            (self.files.len() as f64 / opens).min(1.0) as f32,
            (self.persistence_hits / opens).min(1.0) as f32,
            (self.net / execs).min(1.0) as f32,
        ]
    }
}

/* ================================================================ */
/*  Heuristic teachers (transparent labels for online training)      */
/* ================================================================ */

/// Heuristic ransomware class from the 10-feature embedding.
///
/// Indexes match the `ransomware` module outputs: 0 benign, 1 suspicious,
/// 2 ransomware. The neural head trains against this teacher — the MLP
/// generalises it and keeps scoring between alerts.
pub fn ransomware_heuristic_target(f: &[f32; 10]) -> usize {
    // Distinct-file spread only signals mass encryption when the open rate
    // is high too — a quiet process opening distinct files is just normal work.
    let mass_encryption = f[7] * f[0];
    let score =
        3.0 * f[0] + 2.0 * f[3] + 1.5 * mass_encryption + 1.0 * f[6] + 1.0 * f[2] + 0.5 * f[4];
    if score >= 2.0 {
        2
    } else if score >= 1.0 {
        1
    } else {
        0
    }
}

/// Heuristic lateral-movement class: 0 normal, 1 suspect. Weighs exec +
/// network rate and the network fraction of events.
pub fn lateral_heuristic_target(f: &[f32; 10]) -> usize {
    let score = 2.0 * f[1] + 1.5 * f[9] + 0.5 * f[0];
    if score >= 1.0 {
        1
    } else {
        0
    }
}

/// Heuristic persistence class: 0 normal, 1 suspect. Weighs autostart-path
/// hits, filesystem mutation and destructive ops.
pub fn persistence_heuristic_target(f: &[f32; 10]) -> usize {
    let score = 2.5 * f[8] + 1.0 * f[5] + 0.5 * f[6];
    if score >= 1.0 {
        1
    } else {
        0
    }
}

/* ================================================================ */
/*  Mlp — a generic multi-layer perceptron                           */
/* ================================================================ */

/// A generic feed-forward multi-layer perceptron, hand-rolled on flat
/// `Vec<f32>` storage (row-major `weights[k][i * n_out + j]`).
///
/// * Hidden layers use ReLU; the output layer uses softmax.
/// * Training is online stochastic gradient descent (backpropagation)
///   with cross-entropy loss — exactly what a small embedded model needs.
/// * Initialisation is seeded and deterministic: two `new()` calls with the
///   same `arch` produce identical weights (reproducible tests).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Mlp {
    version: u32,
    arch: Vec<usize>,
    weights: Vec<Vec<f32>>,
    biases: Vec<Vec<f32>>,
}

impl Mlp {
    /// Create a randomly-initialised network with the given layer sizes.
    pub fn new(arch: &[usize]) -> Self {
        assert!(
            arch.len() >= 2,
            "an MLP needs at least an input and output layer"
        );
        let mut state: u64 = 0x5EED_5EED_0000_0001;
        let mut weights = Vec::with_capacity(arch.len() - 1);
        let mut biases = Vec::with_capacity(arch.len() - 1);

        for k in 0..arch.len() - 1 {
            let (n_in, n_out) = (arch[k], arch[k + 1]);
            let mut w = vec![0.0f32; n_in * n_out];
            for v in w.iter_mut() {
                *v = lcg_next(&mut state) * 0.2 - 0.1;
            }
            let mut b = vec![0.0f32; n_out];
            for v in b.iter_mut() {
                *v = lcg_next(&mut state) * 0.02 - 0.01;
            }
            weights.push(w);
            biases.push(b);
        }

        Self {
            version: 1,
            arch: arch.to_vec(),
            weights,
            biases,
        }
    }

    /// Layer sizes, e.g. `[10, 24, 16, 3]`.
    /// Surfaced by the web REST API ([`crate::monitor::Monitor::memlp_summary`]).
    #[allow(dead_code)]
    pub fn arch(&self) -> &[usize] {
        &self.arch
    }

    /// Total number of trainable parameters.
    pub fn param_count(&self) -> usize {
        self.weights.iter().map(|w| w.len()).sum::<usize>()
            + self.biases.iter().map(|b| b.len()).sum::<usize>()
    }

    /// Forward pass: `input` → probability distribution over outputs.
    pub fn forward(&self, input: &[f32]) -> Vec<f32> {
        let mut h = input.to_vec();
        let last = self.weights.len() - 1;
        for (k, w) in self.weights.iter().enumerate() {
            let n_out = self.arch[k + 1];
            let mut z = vec![0.0f32; n_out];
            for (i, hi) in h.iter().enumerate() {
                if *hi == 0.0 {
                    continue;
                }
                let row = &w[i * n_out..(i + 1) * n_out];
                for (zj, rj) in z.iter_mut().zip(row.iter()) {
                    *zj += hi * rj;
                }
            }
            for (zj, bj) in z.iter_mut().zip(self.biases[k].iter()) {
                *zj += bj;
            }
            h = if k == last {
                return softmax(&z);
            } else {
                z.into_iter()
                    .map(|x| if x > 0.0 { x } else { 0.0 })
                    .collect()
            };
        }
        unreachable!("an MLP always has at least one weight layer")
    }

    /// Replace any non-finite (NaN/Inf) weight with `0.0`.
    ///
    /// Recovers a model from a numerical blow-up instead of letting NaN
    /// poison the checkpoint file (serde_json serialises NaN as JSON
    /// `null`, which corrupts the file on reload).
    pub fn sanitize(&mut self) {
        for w in self.weights.iter_mut() {
            for v in w.iter_mut() {
                if !v.is_finite() {
                    *v = 0.0;
                }
            }
        }
        for b in self.biases.iter_mut() {
            for v in b.iter_mut() {
                if !v.is_finite() {
                    *v = 0.0;
                }
            }
        }
    }

    /// One gradient-descent step on a single sample. Returns the
    /// cross-entropy loss before the update (lower = better fit).
    ///
    /// Numerically hardened: inputs are validated, gradients are clipped and
    /// weight updates are bounded, so a single extreme sample (or a long
    /// training run) can never explode the weights into NaN/Inf.
    pub fn train(&mut self, input: &[f32], target: &[f32], learning_rate: f32) -> f32 {
        // Guard against poisoned inputs (NaN/Inf features or labels) — skip
        // the update entirely instead of propagating the poison.
        if !input.iter().chain(target.iter()).all(|v| v.is_finite()) {
            return f32::INFINITY;
        }

        let layers = self.weights.len();

        // Forward pass, remembering pre-activations for the ReLU backprop.
        let mut acts: Vec<Vec<f32>> = Vec::with_capacity(layers + 1);
        let mut pres: Vec<Vec<f32>> = Vec::with_capacity(layers);
        acts.push(input.to_vec());
        for k in 0..layers {
            let n_out = self.arch[k + 1];
            let mut z = vec![0.0f32; n_out];
            for (i, hi) in acts[k].iter().enumerate() {
                if *hi == 0.0 {
                    continue;
                }
                let row = &self.weights[k][i * n_out..(i + 1) * n_out];
                for (zj, rj) in z.iter_mut().zip(row.iter()) {
                    *zj += hi * rj;
                }
            }
            for (zj, bj) in z.iter_mut().zip(self.biases[k].iter()) {
                *zj += bj;
            }
            pres.push(z.clone());
            acts.push(if k == layers - 1 {
                softmax(&z)
            } else {
                z.into_iter()
                    .map(|x| if x > 0.0 { x } else { 0.0 })
                    .collect()
            });
        }

        // Cross-entropy loss.
        let out = &acts[layers];
        let loss: f32 = target
            .iter()
            .zip(out.iter())
            .map(|(&t, &p)| -(t * p.max(1e-7).ln()))
            .sum();

        // Softmax + cross-entropy gradient is simply (p - t), clipped so a
        // single bad sample cannot explode the weights.
        let mut delta: Vec<f32> = out
            .iter()
            .zip(target.iter())
            .map(|(&p, &t)| (p - t).clamp(-5.0, 5.0))
            .collect();

        // Backpropagation, layer by layer.
        for k in (0..layers).rev() {
            let n_in = self.arch[k];
            let n_out = self.arch[k + 1];
            let h_prev = &acts[k];
            for (j, dj) in delta.iter().enumerate() {
                if *dj == 0.0 {
                    continue;
                }
                for (i, hi) in h_prev.iter().enumerate() {
                    // Bound the per-parameter update: a long training run can
                    // never push a single weight past ±1 per sample.
                    let update = (learning_rate * dj * hi).clamp(-1.0, 1.0);
                    self.weights[k][i * n_out + j] -= update;
                }
                self.biases[k][j] -= (learning_rate * dj).clamp(-1.0, 1.0);
            }

            if k > 0 {
                // Gradient through the previous layer's ReLU.
                let mut nd = vec![0.0f32; n_in];
                for (i, pre) in pres[k - 1].iter().enumerate() {
                    let row = &self.weights[k][i * n_out..(i + 1) * n_out];
                    let acc: f32 = delta.iter().zip(row.iter()).map(|(d, r)| d * r).sum();
                    nd[i] = if *pre <= 0.0 { 0.0 } else { acc };
                }
                delta = nd;
            }
        }

        if !loss.is_finite() {
            // Numerical blow-up despite the clipping — reset the offending
            // weights instead of letting NaN poison the checkpoint.
            self.sanitize();
            return 0.0;
        }

        loss
    }
}

/* ================================================================ */
/*  MeMLP — the modular model container                              */
/* ================================================================ */

/// The modular container: several specialist MLP heads sharing one
/// JSON checkpoint. Add a new capability by adding a new module here.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MeMLP {
    pub version: u32,
    pub ransomware: Mlp,
    pub lateral: Mlp,
    pub persistence: Mlp,
    /// Number of online training observations applied so far.
    #[serde(default)]
    pub training_samples: u64,
}

/// A single-module verdict attached to alerts and surfaced in the TUI,
/// JSON output and the web dashboard.
#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    /// Module name: "ransomware", "lateral" or "persistence".
    pub module: &'static str,
    /// Argmax class index of the module output.
    pub class: usize,
    /// Human-readable class label.
    pub label: &'static str,
    /// Probability of the winning class (0.0–1.0).
    pub confidence: f32,
}

/// One [`MeMLP::assess`] result: verdicts from every specialist module.
#[derive(Debug, Clone, Serialize)]
pub struct Assessment {
    pub ransomware: Verdict,
    pub lateral: Verdict,
    pub persistence: Verdict,
}

impl Assessment {
    /// Compact one-line summary for logs, TUI and plain output, e.g.
    /// `R:ransomware 87% L:normal 99% P:normal 99%`.
    pub fn summary(&self) -> String {
        fn part(v: &Verdict, tag: &str) -> String {
            format!("{}:{} {:.0}%", tag, v.label, v.confidence * 100.0)
        }
        format!(
            "{} {} {}",
            part(&self.ransomware, "R:"),
            part(&self.lateral, "L:"),
            part(&self.persistence, "P:")
        )
    }

    /// True when any module flags its top suspicion class.
    pub fn is_threat(&self) -> bool {
        self.ransomware.label == "ransomware"
            || self.lateral.label == "suspect"
            || self.persistence.label == "suspect"
    }
}

impl MeMLP {
    /// Replace every non-finite weight in every module with `0.0`.
    /// Recovery API — also exercised by unit tests after extreme-input training.
    #[allow(dead_code)]
    pub fn sanitize(&mut self) {
        self.ransomware.sanitize();
        self.lateral.sanitize();
        self.persistence.sanitize();
    }

    /// A fresh modular model: deep ransomware net + lateral + persistence heads.
    pub fn new() -> Self {
        Self {
            version: MEMLP_VERSION,
            ransomware: Mlp::new(&RANSOMWARE_ARCH),
            lateral: Mlp::new(&LATERAL_ARCH),
            persistence: Mlp::new(&PERSISTENCE_ARCH),
            training_samples: 0,
        }
    }

    /// Load a checkpoint from disk. Returns a fresh model if the file is
    /// missing, and rejects (with an error) unreadable or wrong-version
    /// checkpoints so a corrupted file never silently resets training.
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be parsed, or if the
    /// checkpoint version differs from [`MEMLP_VERSION`].
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read MeMLP checkpoint {}", path.display()))?;
        let model: MeMLP = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse MeMLP checkpoint {}", path.display()))?;
        if model.version != MEMLP_VERSION {
            anyhow::bail!(
                "MeMLP checkpoint {} has version {}, expected {} — remove the file to retrain",
                path.display(),
                model.version,
                MEMLP_VERSION
            );
        }
        Ok(model)
    }

    /// Persist the checkpoint as pretty JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)
            .with_context(|| format!("failed to write MeMLP checkpoint {}", path.display()))
    }

    /// Total trainable parameters across every module.
    pub fn param_count(&self) -> usize {
        self.ransomware.param_count() + self.lateral.param_count() + self.persistence.param_count()
    }

    /// Classify one behavioural embedding without training.
    pub fn assess(&self, f: &[f32; 10]) -> Assessment {
        Assessment {
            ransomware: ransomware_verdict(&self.ransomware.forward(f)),
            lateral: lateral_verdict(&self.lateral.forward(f)),
            persistence: persistence_verdict(&self.persistence.forward(f)),
        }
    }

    /// One online training step for all modules against the heuristic
    /// teachers. Returns the per-module losses (lower = better fit).
    pub fn train_observation(&mut self, f: &[f32; 10], learning_rate: f32) -> [f32; 3] {
        let r = self.ransomware.train(
            f,
            &one_hot(ransomware_heuristic_target(f), RANSOMWARE_CLASSES),
            learning_rate,
        );
        let l = self
            .lateral
            .train(f, &one_hot(lateral_heuristic_target(f), 2), learning_rate);
        let p = self.persistence.train(
            f,
            &one_hot(persistence_heuristic_target(f), 2),
            learning_rate,
        );
        self.training_samples += 1;
        [r, l, p]
    }
}

impl Default for MeMLP {
    fn default() -> Self {
        Self::new()
    }
}

/* ================================================================ */
/*  Verdict helpers                                                  */
/* ================================================================ */

const RANSOMWARE_LABELS: [&str; 3] = ["benign", "suspicious", "ransomware"];
const BINARY_LABELS: [&str; 2] = ["normal", "suspect"];

/// Build a `ransomware`-module verdict from its softmax output.
pub fn ransomware_verdict(probs: &[f32]) -> Verdict {
    Verdict {
        module: "ransomware",
        class: argmax(probs),
        label: RANSOMWARE_LABELS[argmax(probs).min(2)],
        confidence: probs.get(argmax(probs)).copied().unwrap_or(0.0),
    }
}

/// Build a `lateral`-module verdict from its softmax output.
pub fn lateral_verdict(probs: &[f32]) -> Verdict {
    Verdict {
        module: "lateral",
        class: argmax(probs),
        label: BINARY_LABELS[argmax(probs).min(1)],
        confidence: probs.get(argmax(probs)).copied().unwrap_or(0.0),
    }
}

/// Build a `persistence`-module verdict from its softmax output.
pub fn persistence_verdict(probs: &[f32]) -> Verdict {
    Verdict {
        module: "persistence",
        class: argmax(probs),
        label: BINARY_LABELS[argmax(probs).min(1)],
        confidence: probs.get(argmax(probs)).copied().unwrap_or(0.0),
    }
}

/* ================================================================ */
/*  Helpers                                                          */
/* ================================================================ */

/// Deterministic LCG step used for weight initialisation.
fn lcg_next(state: &mut u64) -> f32 {
    *state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
    (((*state / 65_536) % 32_768) as f32) / 32_767.0
}

/// Numerically-stable softmax over a vector.
fn softmax(x: &[f32]) -> Vec<f32> {
    let max = x.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let exps: Vec<f32> = x.iter().map(|&v| (v - max).exp()).collect();
    let sum: f32 = exps.iter().sum();
    if sum > 0.0 {
        exps.iter().map(|&e| e / sum).collect()
    } else {
        vec![1.0 / x.len() as f32; x.len()]
    }
}

/// Index of the largest probability in a distribution.
pub fn argmax(probs: &[f32]) -> usize {
    probs
        .iter()
        .enumerate()
        .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(i, _)| i)
        .unwrap_or(0)
}

/// One-hot vector of length `n` for class `class`.
pub fn one_hot(class: usize, n: usize) -> Vec<f32> {
    let mut v = vec![0.0f32; n];
    if class < n {
        v[class] = 1.0;
    }
    v
}

/* ================================================================ */
/*  Tests                                                            */
/* ================================================================ */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mlp_forward_is_a_valid_distribution() {
        let mlp = Mlp::new(&RANSOMWARE_ARCH);
        let out = mlp.forward(&[0.5; 10]);
        assert_eq!(out.len(), 3);
        let sum: f32 = out.iter().sum();
        assert!((sum - 1.0).abs() < 1e-4);
        assert!(out.iter().all(|&p| (0.0..=1.0).contains(&p)));
    }

    #[test]
    fn mlp_init_is_deterministic() {
        let a = Mlp::new(&LATERAL_ARCH);
        let b = Mlp::new(&LATERAL_ARCH);
        assert_eq!(a.param_count(), b.param_count());
        assert_eq!(
            a.weights, b.weights,
            "same arch must initialise identically"
        );
    }

    #[test]
    fn mlp_trains_and_loss_decreases() {
        let mut mlp = Mlp::new(&[2, 6, 4, 2]);
        let input = [1.0, 0.0];
        let target = [1.0, 0.0];
        let loss1 = mlp.train(&input, &target, 0.1);
        let loss2 = mlp.train(&input, &target, 0.1);
        assert!(
            loss2 <= loss1 * 1.05,
            "loss should decrease: {loss1} -> {loss2}"
        );
    }

    #[test]
    fn mlp_learns_a_simple_pattern() {
        let mut mlp = Mlp::new(&[2, 8, 4]);
        let (input, target) = ([0.9, 0.1], [0.0, 1.0, 0.0, 0.0]);
        let mut last = f32::MAX;
        for _ in 0..200 {
            last = mlp.train(&input, &target, 0.2);
        }
        assert!(
            last < 0.2,
            "model should fit the pattern, final loss {last}"
        );
        assert_eq!(argmax(&mlp.forward(&input)), 1);
    }

    #[test]
    fn memlp_json_roundtrip() {
        let mut model = MeMLP::new();
        for _ in 0..5 {
            model.train_observation(&[0.5; 10], 0.05);
        }
        let json = serde_json::to_string(&model).unwrap();
        let loaded: MeMLP = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.version, MEMLP_VERSION);
        assert_eq!(loaded.param_count(), model.param_count());
        assert_eq!(loaded.training_samples, model.training_samples);
        let feats = [0.3, 0.5, 0.6, 0.7, 0.2, 0.4, 0.8, 0.5, 0.1, 0.2];
        assert_eq!(
            loaded.ransomware.forward(&feats),
            model.ransomware.forward(&feats)
        );
    }

    #[test]
    fn memlp_checkpoint_save_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("talus-memlp-test-{}", std::process::id()));
        let path = dir.join("memlp.json");
        let mut model = MeMLP::new();
        model.train_observation(&[0.9, 0.9, 0.8, 0.5, 0.5, 0.4, 0.4, 0.9, 0.0, 0.1], 0.05);
        model.save(&path).unwrap();
        let loaded = MeMLP::load(&path).unwrap();
        assert_eq!(loaded.param_count(), model.param_count());
        assert_eq!(loaded.training_samples, model.training_samples);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn memlp_load_missing_file_returns_fresh_model() {
        let model = MeMLP::load(Path::new("/nonexistent/talus/memlp.json")).unwrap();
        assert_eq!(model.version, MEMLP_VERSION);
        assert_eq!(model.training_samples, 0);
    }

    #[test]
    fn training_survives_extreme_inputs_without_nan() {
        let mut model = MeMLP::new();
        for _ in 0..50 {
            model.train_observation(
                &[1e6, -1e6, 1e5, -1e5, 1e4, -1e4, 1e3, -1e3, 1.0, 0.0],
                0.05,
            );
        }
        model.sanitize();
        let json = serde_json::to_string(&model).unwrap();
        assert!(
            !json.contains("null"),
            "NaN weights would serialise as null: {json}"
        );
        let loaded: MeMLP = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.param_count(), model.param_count());
    }

    #[test]
    fn training_skips_nan_inputs_without_touching_weights() {
        let mut mlp = Mlp::new(&[2, 4, 2]);
        let before = mlp.clone();
        let loss = mlp.train(&[f32::NAN, 0.5], &[1.0, 0.0], 0.1);
        assert!(loss.is_infinite(), "poisoned input must be rejected");
        assert_eq!(mlp.weights, before.weights, "weights must stay untouched");
    }

    #[test]
    fn sanitize_clears_nan_and_inf() {
        let mut mlp = Mlp::new(&[2, 4, 2]);
        mlp.weights[0][0] = f32::NAN;
        mlp.weights[1][1] = f32::INFINITY;
        mlp.biases[0][0] = f32::NEG_INFINITY;
        mlp.sanitize();
        assert!(mlp.weights.iter().all(|w| w.iter().all(|v| v.is_finite())));
        assert!(mlp.biases.iter().all(|b| b.iter().all(|v| v.is_finite())));
    }

    #[test]
    fn pid_features_embedding_stays_in_unit_range() {
        let mut pf = PidFeatures::default();
        for i in 0..120 {
            pf.observe_open(
                &format!("/tmp/file{i}.enc"),
                Some("enc"),
                1.5, // out-of-range entropy must be clamped
            );
            pf.observe_exec(i % 2 == 0);
            pf.observe_fs(i % 3 == 0);
        }
        let f = pf.features();
        assert_eq!(f.len(), 10);
        assert!(
            f.iter().all(|v| (0.0..=1.0).contains(v)),
            "features out of range: {f:?}"
        );
    }

    #[test]
    fn pid_features_flags_ransomware_and_persistence_shapes() {
        let mut pf = PidFeatures::default();
        for i in 0..50 {
            pf.observe_open(&format!("/home/u/docs/f{i}.locked"), Some("locked"), 0.9);
        }
        pf.observe_open("/etc/systemd/system/evil.service", Some("service"), 0.4);
        let f = pf.features();
        assert!(
            f[3] > 0.5,
            "ransomware-marker fraction should dominate: {}",
            f[3]
        );
        assert!(f[2] > 0.5, "high-entropy filenames expected: {}", f[2]);
        assert!(f[8] > 0.0, "persistence path should register: {}", f[8]);
        assert_eq!(
            ransomware_heuristic_target(&f),
            2,
            "should be flagged ransomware"
        );
    }

    #[test]
    fn pid_features_quiet_process_is_benign() {
        let mut pf = PidFeatures::default();
        for i in 0..6 {
            pf.observe_open(&format!("/home/u/notes/note{i}.txt"), Some("txt"), 0.2);
        }
        let f = pf.features();
        assert_eq!(
            ransomware_heuristic_target(&f),
            0,
            "quiet process must stay benign"
        );
        assert_eq!(persistence_heuristic_target(&f), 0);
        assert_eq!(lateral_heuristic_target(&f), 0);
    }

    #[test]
    fn pid_features_decay_halves_counters() {
        let mut pf = PidFeatures::default();
        for i in 0..10 {
            pf.observe_open(&format!("/tmp/f{i}.log"), Some("log"), 0.1);
        }
        pf.decay();
        assert!(
            (pf.opens - 5.0).abs() < 1e-9,
            "decay must halve opens: {}",
            pf.opens
        );
    }

    #[test]
    fn heuristic_targets_stay_in_range() {
        for i in 0..500u32 {
            let feats = [
                (i as f32 / 500.0).fract(),
                (i as f32 * 0.37).fract() * 0.5,
                (i as f32 * 0.71).fract(),
                (i as f32 * 0.43).fract(),
                0.5,
                0.5,
                0.7,
                0.5,
                (i as f32 * 0.11).fract(),
                (i as f32 * 0.23).fract(),
            ];
            assert!(ransomware_heuristic_target(&feats) < RANSOMWARE_CLASSES);
            assert!(lateral_heuristic_target(&feats) < 2);
            assert!(persistence_heuristic_target(&feats) < 2);
        }
    }

    #[test]
    fn assess_produces_all_module_verdicts() {
        let model = MeMLP::new();
        let a = model.assess(&[0.5; 10]);
        assert_eq!(a.ransomware.module, "ransomware");
        assert_eq!(a.lateral.module, "lateral");
        assert_eq!(a.persistence.module, "persistence");
        assert!(a.ransomware.confidence >= 0.0 && a.ransomware.confidence <= 1.0);
    }

    #[test]
    fn param_count_matches_architectures() {
        let model = MeMLP::new();
        let expected = 10 * 24
            + 24
            + 24 * 16
            + 16
            + 16 * 3
            + 3
            + 10 * 12
            + 12
            + 12 * 2
            + 2
            + 10 * 12
            + 12
            + 12 * 2
            + 2;
        assert_eq!(model.param_count(), expected);
    }
}
