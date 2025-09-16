use std::{
    io::{
        self,
        ErrorKind,
    },
    path::Path,
    process::Command,
};

use chrono::Utc;
#[cfg(target_os = "windows")]
use winres::WindowsResource;

#[cfg(target_os = "windows")]
const APP_MANIFEST: &'static str = r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <description>PubgValthrun-image-dumper</description>
  <assemblyIdentity type="win32" name="dev.wolveringer.valthrun.pubg.image-dumper" version="0.4.5.0" />
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
      <security>
          <requestedPrivileges>
              <requestedExecutionLevel level="asInvoker" uiAccess="false" />
          </requestedPrivileges>
      </security>
  </trustInfo>
  <asmv3:application xmlns:asmv3="urn:schemas-microsoft-com:asm.v3">
    <asmv3:windowsSettings xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">
      <dpiAware>True/PM</dpiAware>
    </asmv3:windowsSettings>
  </asmv3:application>
</assembly>
"#;

fn main() -> io::Result<()> {
    {
        let git_hash = if Path::new("../.git").exists() {
            match { Command::new("git").args(&["rev-parse", "HEAD"]).output() } {
                Ok(output) => {
                    let hash_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if hash_str.is_empty() {
                        // If we get empty output even though git command succeeded
                        "0000000".to_string()
                    } else {
                        hash_str
                    }
                }
                Err(error) => {
                    if error.kind() == ErrorKind::NotFound {
                        #[cfg(target_os = "windows")]
                        eprintln!("\n\nBuilding the image-dumper requires git.exe to be installed and available in PATH.\nPlease install https://gitforwindows.org.\n\n");

                        #[cfg(target_os = "linux")]
                        eprintln!("\n\nBuilding the image-dumper requires git to be installed and available in PATH.\nPlease install git using your distribution's package manager.\n\n");

                        "0000000".to_string() // Continue with default hash instead of panicking
                    } else {
                        eprintln!("Error running git command: {}", error);
                        "0000000".to_string() // Continue with default hash instead of panicking
                    }
                }
            }
        } else {
            eprintln!("No .git directory found, using default hash");
            "0000000".to_string()
        };

        let git_hash = if git_hash.len() < 7 {
            eprintln!("Git hash too short ({}), using default", git_hash);
            "0000000".to_string()
        } else {
            git_hash
        };

        let build_time = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

        println!("cargo:rustc-env=GIT_HASH={}", &git_hash[0..7]);
        println!("cargo:rustc-env=BUILD_TIME={}", build_time);
    }

    // Windows-specific resource compilation
    #[cfg(target_os = "windows")]
    {
        let mut resource = WindowsResource::new();
        //resource.set_icon("./resources/app-icon.ico");
        resource.set_manifest(APP_MANIFEST);
        resource.compile()?;
    }

    // Make sure we rebuild if this script changes
    println!("cargo:rerun-if-changed=build.rs");
    Ok(())
}
