//! *Read and write user-specific application data*
//!
//! This crate allows Rust developers to store and retrieve user-local preferences and other
//! application data in a flexible and platform-appropriate way.
//!
//! Though it was originally inspired by Java's convenient
//! [Preferences API](https://docs.oracle.com/javase/8/docs/api/java/util/prefs/Preferences.html),
//! this crate is more flexible. *Any* struct or enum that implements
//! [`serde`][serde-api]'s `Serialize` and `Deserialize`
//! traits can be stored and retrieved as user data. Implementing those traits is
//! trivial; just include the crate `serde_derive` (don't forget `#[macro_use]`!) and add
//! `#[derive(Serialize, Deserialize)` to your struct definition. (See examples below.)
//!
//! # Usage
//! For convenience, the type [`PreferencesMap<T>`](type.PreferencesMap.html) is provided. (It's
//! actually just [`std::collections::HashMap<String, T>`][hashmap-api], where `T` defaults to
//! `String`). This mirrors the Java API, which models user data as an opaque key-value store. As
//! long as  `T` is serializable and deserializable, [`Preferences`](trait.Preferences.html)
//! will be implemented for your map instance. This allows you to seamlessly save and load
//! user data with the `save(..)` and `load(..)` trait methods from `Preferences`.
//!
//! # Basic example
//! ```
//! extern crate preferences;
//! use preferences::{AppInfo, PreferencesMap, Preferences};
//!
//! const APP_INFO: AppInfo = AppInfo{name: "preferences", author: "Rust language community"};
//!
//! fn main() {
//!
//!     // Create a new preferences key-value map
//!     // (Under the hood: HashMap<String, String>)
//!     let mut faves: PreferencesMap<String> = PreferencesMap::new();
//!
//!     // Edit the preferences (std::collections::HashMap)
//!     faves.insert("color".into(), "blue".into());
//!     faves.insert("programming language".into(), "Rust".into());
//!
//!     // Store the user's preferences
//!     let prefs_key = "tests/docs/basic-example";
//!     let save_result = faves.save(&APP_INFO, prefs_key);
//!     assert!(save_result.is_ok());
//!
//!     // ... Then do some stuff ...
//!
//!     // Retrieve the user's preferences
//!     let load_result = PreferencesMap::<String>::load(&APP_INFO, prefs_key);
//!     assert!(load_result.is_ok());
//!     assert_eq!(load_result.unwrap(), faves);
//!
//! }
//! ```
//!
//! # Using custom data types
//! ```
//! #[macro_use]
//! extern crate serde_derive;
//! extern crate preferences;
//! use preferences::{AppInfo, Preferences};
//!
//! const APP_INFO: AppInfo = AppInfo{name: "preferences", author: "Rust language community"};
//!
//! // Deriving `Serialize` and `Deserialize` on a struct/enum automatically implements
//! // the `Preferences` trait.
//! #[derive(Serialize, Deserialize, PartialEq, Debug)]
//! struct PlayerData {
//!     level: u32,
//!     health: f32,
//! }
//!
//! fn main() {
//!
//!     let player = PlayerData{level: 2, health: 0.75};
//!
//!     let prefs_key = "tests/docs/custom-types";
//!     let save_result = player.save(&APP_INFO, prefs_key);
//!     assert!(save_result.is_ok());
//!
//!     // Method `load` is from trait `Preferences`.
//!     let load_result = PlayerData::load(&APP_INFO, prefs_key);
//!     assert!(load_result.is_ok());
//!     assert_eq!(load_result.unwrap(), player);
//!
//! }
//! ```
//!
//! # Using custom data types with `PreferencesMap`
//! ```
//! #[macro_use]
//! extern crate serde_derive;
//! extern crate preferences;
//! use preferences::{AppInfo, PreferencesMap, Preferences};
//!
//! const APP_INFO: AppInfo = AppInfo{name: "preferences", author: "Rust language community"};
//!
//! #[derive(Serialize, Deserialize, PartialEq, Debug)]
//! struct Point(f32, f32);
//!
//! fn main() {
//!
//!     let mut places = PreferencesMap::new();
//!     places.insert("treasure".into(), Point(1.0, 1.0));
//!     places.insert("home".into(), Point(-1.0, 6.6));
//!
//!     let prefs_key = "tests/docs/custom-types-with-preferences-map";
//!     let save_result = places.save(&APP_INFO, prefs_key);
//!     assert!(save_result.is_ok());
//!
//!     let load_result = PreferencesMap::load(&APP_INFO, prefs_key);
//!     assert!(load_result.is_ok());
//!     assert_eq!(load_result.unwrap(), places);
//!
//! }
//! ```
//!
//! # Using custom data types with serializable containers
//! ```
//! #[macro_use]
//! extern crate serde_derive;
//! extern crate preferences;
//! use preferences::{AppInfo, Preferences};
//!
//! const APP_INFO: AppInfo = AppInfo{name: "preferences", author: "Rust language community"};
//!
//! #[derive(Serialize, Deserialize, PartialEq, Debug)]
//! struct Point(usize, usize);
//!
//! fn main() {
//!
//!     let square = vec![
//!         Point(0,0),
//!         Point(1,0),
//!         Point(1,1),
//!         Point(0,1),
//!     ];
//!
//!     let prefs_key = "tests/docs/custom-types-in-containers";
//!     let save_result = square.save(&APP_INFO, prefs_key);
//!     assert!(save_result.is_ok());
//!
//!     let load_result = Vec::<Point>::load(&APP_INFO, prefs_key);
//!     assert!(load_result.is_ok());
//!     assert_eq!(load_result.unwrap(), square);
//!
//! }
//! ```
//!
//! # Under the hood
//! Data is written to flat files under the active user's home directory in a location specific to
//! the operating system. This location is decided by the `app_dirs` crate with the data type
//! `UserConfig`. Within the data directory, the files are stored in a folder hierarchy that maps
//! to a sanitized version of the preferences key passed to `save(..)`.
//!
//! The data is stored in JSON format. This has several advantages:
//!
//! * Human-readable and self-describing
//! * More compact than e.g. XML
//! * Better adoption rates and language compatibility than e.g. TOML
//! * Not reliant on a consistent memory layout like e.g. binary
//!
//! You could, of course, implement `Preferences` yourself and store your user data in
//! whatever location and format that you wanted. But that would defeat the purpose of this
//! library. &#128522;
//!
//! [hashmap-api]: https://doc.rust-lang.org/nightly/std/collections/struct.HashMap.html
//! [serde-api]: https://crates.io/crates/serde

#![warn(missing_docs)]

extern crate app_dirs;
extern crate serde;
extern crate serde_json;

pub use app_dirs::{AppDirsError, AppInfo};
use app_dirs::{AppDataType, get_data_root, get_app_dir};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt;
use std::fs::{File, create_dir_all};
use std::io::{self, ErrorKind, Read, Write};
use std::path::PathBuf;
use std::string::FromUtf8Error;

const DATA_TYPE: AppDataType = AppDataType::UserConfig;
static PREFS_FILE_EXTENSION: &'static str = ".prefs.json";
static DEFAULT_PREFS_FILENAME: &'static str = "prefs.json";

/// Generic key-value store for user data.
///
/// This is actually a wrapper type around [`std::collections::HashMap<String, T>`][hashmap-api]
/// (with `T` defaulting to `String`), so use the `HashMap` API methods to access and change user
/// data in memory.
///
/// To save or load user data, use the methods defined for the trait
/// [`Preferences`](trait.Preferences.html), which will be automatically implemented for
/// `PreferencesMap<T>` as long as `T` is serializable. (See the
/// [module documentation](index.html) for examples and more details.)
///
/// [hashmap-api]: https://doc.rust-lang.org/nightly/std/collections/struct.HashMap.html
pub type PreferencesMap<T = String> = HashMap<String, T>;

/// Error type representing the errors that can occur when saving or loading user data.
#[derive(Debug)]
pub enum PreferencesError {
    /// An error occurred during JSON serialization or deserialization.
    Json(serde_json::Error),
    /// An error occurred during preferences file I/O.
    Io(io::Error),
    /// Couldn't figure out where to put or find the serialized data.
    Directory(AppDirsError),
}

impl fmt::Display for PreferencesError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use PreferencesError::*;
        match *self {
            Json(ref e) => e.fmt(f),
            Io(ref e) => e.fmt(f),
            Directory(ref e) => e.fmt(f),
        }
    }
}

impl std::error::Error for PreferencesError {
    fn description(&self) -> &str {
        use PreferencesError::*;
        match *self {
            Json(ref e) => e.description(),
            Io(ref e) => e.description(),
            Directory(ref e) => e.description(),
        }
    }
    fn cause(&self) -> Option<&std::error::Error> {
        use PreferencesError::*;
        Some(match *self {
            Json(ref e) => e,
            Io(ref e) => e,
            Directory(ref e) => e,
        })
    }
}

impl From<serde_json::Error> for PreferencesError {
    fn from(e: serde_json::Error) -> Self {
        PreferencesError::Json(e)
    }
}

impl From<FromUtf8Error> for PreferencesError {
    fn from(_: FromUtf8Error) -> Self {
        let kind = ErrorKind::InvalidData;
        let msg = "Preferences file contained invalid UTF-8";
        let err = io::Error::new(kind, msg);
        PreferencesError::Io(err)
    }
}

impl From<std::io::Error> for PreferencesError {
    fn from(e: std::io::Error) -> Self {
        PreferencesError::Io(e)
    }
}

impl From<AppDirsError> for PreferencesError {
    fn from(e: AppDirsError) -> Self {
        PreferencesError::Directory(e)
    }
}

/// Trait for types that can be saved & loaded as user data.
///
/// This type is automatically implemented for any struct/enum `T` which implements both
/// `Serialize` and `Deserialize` (from `serde`). (Trivially, you can annotate the type
/// with `#[derive(Serialize, Deserialize)`). It is encouraged to use the provided
/// type, [`PreferencesMap`](type.PreferencesMap.html), to bundle related user preferences.
///
/// For the `app` parameter of `save(..)` and `load(..)`, it's recommended that you use a single
/// `const` instance of `AppInfo` that represents your program:
///
/// ```
/// use preferences::AppInfo;
/// const APP_INFO: AppInfo = AppInfo{name: "Awesome App", author: "Dedicated Dev"};
/// ```
///
/// The `key` parameter of `save(..)` and `load(..)` should be used to uniquely identify different
/// preferences data. It roughly maps to a platform-dependent directory hierarchy, with forward
/// slashes used as separators on all platforms. Keys are sanitized to be valid paths; to ensure
/// human-readable paths, use only letters, digits, spaces, hyphens, underscores, periods, and
/// slashes.
///
/// # Example keys
/// * `options/graphics`
/// * `saves/quicksave`
/// * `bookmarks/favorites`
pub trait Preferences: Sized {
    /// Saves the current state of this object. Implementation is platform-dependent, but the data
    /// will be local to the active user.
    ///
    /// # Failures
    /// If a serialization or file I/O error (e.g. permission denied) occurs.
    fn save<S: AsRef<str>>(&self, app: &AppInfo, key: S) -> Result<(), PreferencesError>;
    /// Loads this object's state from previously saved user data with the same `key`. This is
    /// an instance method which completely overwrites the object's state with the serialized
    /// data. Thus, it is recommended that you call this method immediately after instantiating
    /// the preferences object.
    ///
    /// # Failures
    /// If a deserialization or file I/O error (e.g. permission denied) occurs, or if no user data
    /// exists at that `path`.
    fn load<S: AsRef<str>>(app: &AppInfo, key: S) -> Result<Self, PreferencesError>;
    /// Same as `save`, but writes the serialized preferences to an arbitrary writer.
    fn save_to<W: Write>(&self, writer: &mut W) -> Result<(), PreferencesError>;
    /// Same as `load`, but reads the serialized preferences from an arbitrary writer.
    fn load_from<R: Read>(reader: &mut R) -> Result<Self, PreferencesError>;
}

fn compute_file_path<S: AsRef<str>>(app: &AppInfo, key: S) -> Result<PathBuf, PreferencesError> {
    let mut path = get_app_dir(DATA_TYPE, app, key.as_ref())?;
    let new_name = match path.file_name() {
        Some(name) if !name.is_empty() => {
            let mut new_name = OsString::with_capacity(name.len() + PREFS_FILE_EXTENSION.len());
            new_name.push(name);
            new_name.push(PREFS_FILE_EXTENSION);
            new_name
        }
        _ => DEFAULT_PREFS_FILENAME.into(),
    };
    path.set_file_name(new_name);
    Ok(path)
}

impl<T> Preferences for T
    where T: Serialize + Deserialize + Sized
{
    fn save<S>(&self, app: &AppInfo, key: S) -> Result<(), PreferencesError>
        where S: AsRef<str>
    {
        let path = compute_file_path(app, key.as_ref())?;
        path.parent().map(create_dir_all);
        let mut file = File::create(path)?;
        self.save_to(&mut file)
    }
    fn load<S: AsRef<str>>(app: &AppInfo, key: S) -> Result<Self, PreferencesError> {
        let path = compute_file_path(app, key.as_ref())?;
        let mut file = File::open(path)?;
        Self::load_from(&mut file)
    }
    fn save_to<W: Write>(&self, writer: &mut W) -> Result<(), PreferencesError> {
        serde_json::to_writer(writer, self).map_err(Into::into)
    }
    fn load_from<R: Read>(reader: &mut R) -> Result<Self, PreferencesError> {
        serde_json::from_reader(reader).map_err(Into::into)
    }
}

/// Get full path to the base directory for preferences.
///
/// This makes no guarantees that the specified directory path actually *exists* (though you can
/// easily use `std::fs::create_dir_all(..)`). Returns `None` if the directory cannot be determined
/// or is not available on the current platform.
pub fn prefs_base_dir() -> Option<PathBuf> {
    get_data_root(AppDataType::UserConfig).ok()
}

#[cfg(test)]
mod tests {
    use {AppInfo, Preferences, PreferencesMap};
    const APP_INFO: AppInfo = AppInfo {
        name: "preferences",
        author: "Rust language community",
    };
    const TEST_PREFIX: &'static str = "tests/module";
    fn gen_test_name(name: &str) -> String {
        TEST_PREFIX.to_owned() + "/" + name
    }
    fn gen_sample_prefs() -> PreferencesMap<String> {
        let mut prefs = PreferencesMap::new();
        prefs.insert("foo".into(), "bar".into());
        prefs.insert("age".into(), "23".into());
        prefs.insert("PI".into(), "3.14".into());
        prefs.insert("offset".into(), "-9".into());
        prefs
    }
    #[test]
    fn test_save_load() {
        let sample_map = gen_sample_prefs();
        let sample_other: i32 = 4;
        let name_map = gen_test_name("save-load-map");
        let name_other = gen_test_name("save-load-other");
        let save_map_result = sample_map.save(&APP_INFO, &name_map);
        let save_other_result = sample_other.save(&APP_INFO, &name_other);
        assert!(save_map_result.is_ok());
        assert!(save_other_result.is_ok());
        let load_map_result = PreferencesMap::load(&APP_INFO, &name_map);
        let load_other_result = i32::load(&APP_INFO, &name_other);
        assert!(load_map_result.is_ok());
        assert!(load_other_result.is_ok());
        assert_eq!(load_map_result.unwrap(), sample_map);
        assert_eq!(load_other_result.unwrap(), sample_other);
    }
}
