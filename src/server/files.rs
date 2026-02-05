use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

pub struct FileManager {
    base_path: PathBuf,
}

impl FileManager {
    pub fn new(base_path: impl Into<PathBuf>) -> Self {
        Self {
            base_path: base_path.into(),
        }
    }
    // Chunk reading
    pub fn create_file(&self, filename: &str) -> io::Result<std::fs::File> {
        let filename = match self.sanitize_filename(filename) {
            Some(f) => f,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid filename",
                ));
            }
        };
        let path = self.base_path.join(filename);

        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
    }

    pub fn append_chunk(file: &mut std::fs::File, chunk: &[u8]) -> io::Result<()> {
        file.write_all(chunk)
    }

    pub fn list_files_formatted(&self) -> String {
        let mut output = String::from(
            "\n  ======================== Available Files ========================\n\n",
        );

        let entries = match fs::read_dir(&self.base_path) {
            Ok(entries) => entries,
            Err(e) => {
                output.push_str(&format!("[ERROR] Cannot read directory: {}\n", e));
                return output;
            }
        };

        // Read available files
        let mut files: Vec<String> = Vec::new();
        for entry in entries.flatten() {
            let path: PathBuf = entry.path();
            if path.is_file() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    files.push(name.to_string());
                }
            }
        }

        if files.is_empty() {
            output.push_str("[INFO] No files available.\n");
            return output;
        }

        let max_len = files.iter().map(|f| f.len()).max().unwrap_or(10);
        let col_width = max_len + 6; // margen entre columnas

        for (i, filename) in files.iter().enumerate() {
            output.push_str(&format!("   • {:<width$}", filename, width = col_width));
            if (i + 1) % 2 == 0 {
                output.push('\n');
            }
        }

        if files.len() % 2 != 0 {
            output.push('\n');
        }

        output
    }
    // Verify filename and purge malicious content
    fn sanitize_filename(&self, name: &str) -> Option<String> {
        if name.contains('/') || name.contains('\\') || name.contains("..") {
            return None;
        }
        Some(name.to_string())
    }

    pub fn file_exists(&self, name: &str) -> bool {
        if self.sanitize_filename(name).is_none() {
            return false;
        }

        let path = self.base_path.join(name);
        path.exists() && path.is_file()
    }

    pub fn read_file(&self, name: &str) -> io::Result<Vec<u8>> {
        if self.sanitize_filename(name).is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid filename",
            ));
        }

        let mut path = self.base_path.clone();
        path.push(name);

        let mut file = fs::File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        Ok(buffer)
    }
}
