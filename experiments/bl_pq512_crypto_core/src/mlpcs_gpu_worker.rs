//! Bounded untrusted CUDA transport for production MLPCS folds.

use std::{
    ffi::OsStr,
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

use crate::field::Fp16;

const READY: &[u8; 8] = b"BLMLGPU1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlpcsGpuWorkerError {
    Spawn,
    Io,
    Protocol,
    Shape,
    WorkerExit,
}

pub struct MlpcsGpuWorker {
    child: Child,
    stdin: BufWriter<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    round: usize,
}

impl MlpcsGpuWorker {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        python: &Path,
        worker: &Path,
        runtime: &OsStr,
        input_codeword: &Path,
        output_codeword: &Path,
        main_mixing: Fp16,
        auxiliary_mixing: Fp16,
        auxiliary_codeword: &[Fp16],
    ) -> Result<Self, MlpcsGpuWorkerError> {
        if auxiliary_codeword.len() != 1 << 21 {
            return Err(MlpcsGpuWorkerError::Shape);
        }
        let mut child = Command::new(python)
            .arg("-I")
            .arg(worker)
            .arg(runtime)
            .arg(input_codeword)
            .arg(output_codeword)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|_| MlpcsGpuWorkerError::Spawn)?;
        let child_stdin = child.stdin.take().ok_or(MlpcsGpuWorkerError::Spawn)?;
        let child_stdout = child.stdout.take().ok_or(MlpcsGpuWorkerError::Spawn)?;
        let mut result = Self {
            child,
            stdin: BufWriter::with_capacity(16 << 20, child_stdin),
            stdout: BufReader::with_capacity(16 << 20, child_stdout),
            round: 0,
        };
        result.write_value(main_mixing)?;
        result.write_value(auxiliary_mixing)?;
        for value in auxiliary_codeword {
            result.write_value(*value)?;
        }
        result.stdin.flush().map_err(|_| MlpcsGpuWorkerError::Io)?;
        result.read_ready()?;
        Ok(result)
    }

    pub fn fold(&mut self, challenge: Fp16) -> Result<(), MlpcsGpuWorkerError> {
        if self.round >= 22 {
            return Err(MlpcsGpuWorkerError::Shape);
        }
        self.stdin
            .write_all(b"F")
            .and_then(|_| self.stdin.write_all(&(self.round as u32).to_be_bytes()))
            .map_err(|_| MlpcsGpuWorkerError::Io)?;
        self.write_value(challenge)?;
        self.stdin.flush().map_err(|_| MlpcsGpuWorkerError::Io)?;
        self.read_ready()?;
        self.round += 1;
        Ok(())
    }

    pub fn stream_layer<T>(
        &mut self,
        consume: impl FnOnce(&mut dyn Read, usize) -> Result<T, MlpcsGpuWorkerError>,
    ) -> Result<T, MlpcsGpuWorkerError> {
        self.stdin
            .write_all(b"S")
            .and_then(|_| self.stdin.flush())
            .map_err(|_| MlpcsGpuWorkerError::Io)?;
        let mut encoded_count = [0_u8; 8];
        self.stdout
            .read_exact(&mut encoded_count)
            .map_err(|_| MlpcsGpuWorkerError::Io)?;
        let count = usize::try_from(u64::from_be_bytes(encoded_count))
            .map_err(|_| MlpcsGpuWorkerError::Shape)?;
        if count != (1_usize << 25) >> self.round {
            return Err(MlpcsGpuWorkerError::Protocol);
        }
        consume(&mut self.stdout, count)
    }

    pub fn reset(&mut self, main_mixing: Fp16) -> Result<(), MlpcsGpuWorkerError> {
        self.stdin
            .write_all(b"R")
            .map_err(|_| MlpcsGpuWorkerError::Io)?;
        self.write_value(main_mixing)?;
        self.stdin.flush().map_err(|_| MlpcsGpuWorkerError::Io)?;
        self.read_ready()?;
        self.round = 0;
        Ok(())
    }

    pub fn finish(mut self) -> Result<(), MlpcsGpuWorkerError> {
        self.stdin
            .write_all(b"X")
            .and_then(|_| self.stdin.flush())
            .map_err(|_| MlpcsGpuWorkerError::Io)?;
        let status = self.child.wait().map_err(|_| MlpcsGpuWorkerError::Io)?;
        if status.success() {
            Ok(())
        } else {
            Err(MlpcsGpuWorkerError::WorkerExit)
        }
    }

    fn write_value(&mut self, value: Fp16) -> Result<(), MlpcsGpuWorkerError> {
        self.stdin
            .write_all(&value.encode())
            .map_err(|_| MlpcsGpuWorkerError::Io)
    }

    fn read_ready(&mut self) -> Result<(), MlpcsGpuWorkerError> {
        let mut ready = [0_u8; READY.len()];
        self.stdout
            .read_exact(&mut ready)
            .map_err(|_| MlpcsGpuWorkerError::Io)?;
        if &ready == READY {
            Ok(())
        } else {
            Err(MlpcsGpuWorkerError::Protocol)
        }
    }
}

impl Drop for MlpcsGpuWorker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
