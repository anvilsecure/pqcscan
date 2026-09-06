use rust_embed::RustEmbed;
use tera::{Context, Tera};
use std::fs::{File, OpenOptions};
use std::io;
use chrono::Utc;
use std::path::{Path, PathBuf};
use crate::ReportResults;

const MAX_UNIQUE_ATTEMPTS: u32 = 99;

/// Creates a new file at `path`, refusing to follow or overwrite an existing
/// path (including symlinks) via O_EXCL. If `path` is already taken, tries
/// `path` with `-01`, `-02`, ... appended to the file stem until a free name
/// is found or `MAX_UNIQUE_ATTEMPTS` is exhausted.
fn create_unique_file(path: &Path) -> io::Result<(File, PathBuf)> {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(f) => return Ok((f, path.to_path_buf())),
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
        Err(_) => {}
    }

    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let stem = path.file_stem().unwrap_or_default().to_string_lossy().into_owned();
    let ext = path.extension().map(|e| e.to_string_lossy().into_owned());

    for n in 1..=MAX_UNIQUE_ATTEMPTS {
        let candidate_name = match &ext {
            Some(ext) => format!("{stem}-{n:02}.{ext}"),
            None => format!("{stem}-{n:02}"),
        };
        let candidate = parent.join(candidate_name);
        match OpenOptions::new().write(true).create_new(true).open(&candidate) {
            Ok(f) => return Ok((f, candidate)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("could not find a free filename after {MAX_UNIQUE_ATTEMPTS} attempts based on {}", path.display()),
    ))
}

#[derive(RustEmbed)]
#[folder = "$CARGO_MANIFEST_DIR/support/templates/"]
struct EmbeddedResources;

pub fn generate_report(output_file: &Path, results: ReportResults) -> Result<(), Box<dyn std::error::Error>>
{
    let templates = [
        "macros.html",
        "template.html",
        "ssh_results.html",
        "tls_results.html",
        "summary.html",
    ];
    let mut tera = Tera::default();

    log::debug!("Loading HTML templates");
    for template in templates {
        let html_file = EmbeddedResources::get(template)
            .ok_or_else(|| format!("Embedded template not found: {template}"))?;
        let html_data = std::str::from_utf8(html_file.data.as_ref())?;
        tera.add_raw_template(template, html_data)?;
    }

    let mut ctx = Context::from_serialize(results)?;

    let dt = Utc::now().format("%Y-%m-%d %H:%M:%S %Z").to_string();
    ctx.insert("title", &dt);
    ctx.insert("PQC_SUPPORTED", &crate::PQC_SUPPORTED);

    log::trace!("Tera Template: {:?}", ctx);

    log::debug!("Rendering HTML report to {}", output_file.display());
    let (f, written_path) = create_unique_file(output_file)?;
    if written_path != output_file {
        println!("{} already exists, writing report to {} instead", output_file.display(), written_path.display());
    }
    tera.render_to("template.html", &ctx, f)?;
    log::info!("HTML report written to {}", written_path.display());

    Ok(())
}