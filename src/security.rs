use std::{
    ffi::OsString,
    fs::{create_dir_all, File},
    io::{Read, Write},
    path::PathBuf,
};

use cocoon::{Cocoon, CocoonCipher, Creation};
use app_dirs::{get_app_dir, get_data_root, AppDataType, AppInfo};
use serde::{de::DeserializeOwned, Serialize};

use crate::{PreferencesError, DATA_TYPE, DEFAULT_PREFS_FILENAME, PREFS_FILE_EXTENSION};

pub struct SecurityManager<'a> {
    core: Cocoon<'a, Creation>,
}

impl<'a> SecurityManager<'a> {
    pub fn new(password: &'a str, cipher: Option<CocoonCipher>) -> Self {
        let mut core = Cocoon::new(password.as_bytes());
        if let Some(cipher) = cipher {
            core = core.with_cipher(cipher);
        }
        Self { core }
    }

    pub(super) fn encrypt(&self, value: &str) -> Result<Vec<u8>, cocoon::Error> {
        let mut b = value.to_owned().into_bytes();
        self.core
            .encrypt(&mut b)
            .and_then(|arr| Ok(arr.to_vec()))
    }

    pub(super) fn decrypt(&self, value: &str) -> Result<Vec<u8>, cocoon::Error> {
        let mut result = Vec::new();
        let value = value.to_owned().into_bytes();
        let res = self.core.decrypt(&mut result, &value);
        if res.is_ok() {
            res.unwrap();
            return Ok(result);
        }
        Err(res.unwrap_err())
    }

    pub fn encrypt_str(&self, value: &str) -> Result<String, cocoon::Error> {
        let bytes = self.encrypt(value).unwrap();
        Ok(String::from_utf8(bytes).unwrap())
    }

    pub fn dencrypt_str(&self, value: &str) -> Result<String, cocoon::Error> {
        let bytes = self.decrypt(value).unwrap();
        Ok(String::from_utf8(bytes).unwrap())
    }

    pub(super) fn to_file<W: Write>(&self, data: &str, file: &mut W) ->  Result<(), cocoon::Error> {
        let data = data.to_owned().into_bytes();
        self.core.dump(data, file)
    }

    pub(super) fn from_file<R: Read>(&self, file: &mut R) -> Result<String, cocoon::Error> {
        let bytes = self.core.parse(file).unwrap();
        Ok(String::from_utf8(bytes).unwrap())
    }
}

/// Trait for types that can be saved & loaded encripted as user data.
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
pub trait SecurePreferences: Sized {
    /// Saves the current state of this object. Implementation is platform-dependent, but the data
    /// will be local to the active user.
    ///
    /// # Failures
    /// If a serialization or file I/O error (e.g. permission denied) occurs.
    fn save<S: AsRef<str>>(&self, app: &AppInfo, manager: &SecurityManager, key: S) -> Result<(), PreferencesError>;
    /// Loads this object's state from previously saved user data with the same `key`. This is
    /// an instance method which completely overwrites the object's state with the serialized
    /// data. Thus, it is recommended that you call this method immediately after instantiating
    /// the preferences object.
    ///
    /// # Failures
    /// If a deserialization or file I/O error (e.g. permission denied) occurs, or if no user data
    /// exists at that `path`.
    fn load<S: AsRef<str>>(app: &AppInfo, manager: &SecurityManager, key: S) -> Result<Self, PreferencesError>;
    /// Same as `save`, but writes the encripted preferences to an arbitrary writer.
    fn save_to<W: Write>(&self, manager: &SecurityManager, writer: &mut W) -> Result<(), PreferencesError>;
    /// Same as `load`, but reads the encripted preferences from an arbitrary writer.
    fn load_from<R: Read>(manager: &SecurityManager, reader: &mut R) -> Result<Self, PreferencesError>;
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

impl<T> SecurePreferences for T
where
    T: Serialize + DeserializeOwned + Sized,
{
    fn save<S>(&self, app: &AppInfo, manager: &SecurityManager, key: S) -> Result<(), PreferencesError>
    where
        S: AsRef<str>,
    {
        let path = compute_file_path(app, key.as_ref())?;
        path.parent().map(create_dir_all);
        let mut file = File::create(path)?;
        self.save_to(manager, &mut file)
    }
    fn load<S: AsRef<str>>(app: &AppInfo, manager: &SecurityManager, key: S) -> Result<Self, PreferencesError> {
        let path = compute_file_path(app, key.as_ref())?;
        let mut file = File::open(path)?;
        Self::load_from(manager, &mut file)
    }
    fn save_to<W: Write>(&self, manager: &SecurityManager, writer: &mut W) -> Result<(), PreferencesError> {
        let str_raw = serde_json::to_string(self).unwrap();
        manager.to_file(&str_raw, writer).map_err(PreferencesError::Security).unwrap();
        Ok(())
    }
    fn load_from<R: Read>(manager: &SecurityManager, reader: &mut R) -> Result<Self, PreferencesError> {
        let decrypt_str = manager.from_file(reader).map_err(PreferencesError::Security).unwrap();
        let data = serde_json::from_str(&decrypt_str).unwrap();
        Ok(data)
    }
}
