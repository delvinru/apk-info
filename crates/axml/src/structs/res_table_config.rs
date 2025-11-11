use std::cmp::Ordering;
use std::fmt::{Display, Write};
use std::hash::Hash;

use bitflags::bitflags;
use log::warn;
use winnow::binary::{le_u32, u8};
use winnow::prelude::*;
use winnow::token::take;

bitflags! {
    /// Bitmask for configuration changes and qualifiers from Android's AConfiguration.
    ///
    /// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#1306>
    #[derive(Debug)]
    pub struct ResTableConfigFlags: u32 {
        /// Bit mask for Mobile Country Code (MCC) configuration.
        /// See: <https://developer.android.com/guide/topics/resources/providing-resources#mcc>
        const CONFIG_MCC = 0x0001;

        /// Bit mask for Mobile Network Code (MNC) configuration.
        /// See: <https://developer.android.com/guide/topics/resources/providing-resources#mnc>
        const CONFIG_MNC = 0x0002;

        /// Bit mask for locale configuration (language and region).
        /// See: <https://developer.android.com/guide/topics/resources/providing-resources#LocaleQualifier>
        const CONFIG_LOCALE = 0x0004;

        /// Bit mask for touchscreen configuration.
        /// See: <https://developer.android.com/guide/topics/resources/providing-resources#TouchscreenQualifier>
        const CONFIG_TOUCHSCREEN = 0x0008;

        /// Bit mask for keyboard type configuration.
        /// See: <https://developer.android.com/guide/topics/resources/providing-resources#ImeQualifier>
        const CONFIG_KEYBOARD = 0x0010;

        /// Bit mask for keyboard availability (hidden/shown).
        /// See: <https://developer.android.com/guide/topics/resources/providing-resources#KeyboardAvailQualifier>
        const CONFIG_KEYBOARD_HIDDEN = 0x0020;

        /// Bit mask for navigation method configuration.
        /// See: <https://developer.android.com/guide/topics/resources/providing-resources#NavigationQualifier>
        const CONFIG_NAVIGATION = 0x0040;

        /// Bit mask for screen orientation configuration.
        /// See: <https://developer.android.com/guide/topics/resources/providing-resources#OrientationQualifier>
        const CONFIG_ORIENTATION = 0x0080;

        /// Bit mask for screen density configuration.
        /// See: <https://developer.android.com/guide/topics/resources/providing-resources#DensityQualifier>
        const CONFIG_DENSITY = 0x0100;

        /// Bit mask for screen size configuration.
        /// See: <https://developer.android.com/guide/topics/resources/providing-resources#ScreenSizeQualifier>
        const CONFIG_SCREEN_SIZE = 0x0200;

        /// Bit mask for smallest screen width configuration.
        /// See: <https://developer.android.com/guide/topics/resources/providing-resources#SmallestScreenWidthQualifier>
        const CONFIG_SMALLEST_SCREEN_SIZE = 0x2000;

        /// Bit mask for platform version configuration.
        /// See: <https://developer.android.com/guide/topics/resources/providing-resources#VersionQualifier>
        const CONFIG_VERSION = 0x0400;

        /// Bit mask for screen layout (long/short, size).
        /// See: <https://developer.android.com/guide/topics/resources/providing-resources#ScreenAspectQualifier>
        const CONFIG_SCREEN_LAYOUT = 0x0800;

        /// Bit mask for UI mode (normal, car, desk, watch, etc.).
        /// See: <https://developer.android.com/guide/topics/resources/providing-resources#UiModeQualifier>
        const CONFIG_UI_MODE = 0x1000;

        /// Bit mask for layout direction (LTR or RTL).
        /// See: <https://developer.android.com/guide/topics/resources/providing-resources#LayoutDirectionQualifier>
        const CONFIG_LAYOUTDIR = 0x4000;

        /// Bit mask for screen roundness (round or not).
        /// See: <https://developer.android.com/guide/topics/resources/providing-resources#ScreenRoundQualifier>
        const CONFIG_SCREEN_ROUND = 0x8000;

        /// Bit mask for wide color gamut and HDR configuration.
        /// See: <https://developer.android.com/guide/topics/resources/providing-resources#WideColorGamutQualifier>
        const CONFIG_COLOR_MODE = 0x10000;

        /// Bit mask for grammatical gender configuration.
        /// See: <https://developer.android.com/guide/topics/resources/providing-resources#GrammaticalInflectionQualifier>
        const CONFIG_GRAMMATICAL_GENDER = 0x20000;

        /// Additional flag indicating an entry is public
        const SPEC_PUBLIC = 0x40000000;

        /// Additional flag indicating the resource id for this resource may change in a future build.
        /// If this flag is set, the SPEC_PUBLIC flag is also set since the resource must be
        /// public to be exposed as an API to other applications.
        const SPEC_STAGED_API = 0x20000000;
    }
}

/// Grammatical gender configuration flags
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/native/include/android/configuration.h?fi=ACONFIGURATION_VERSION#489>
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum GrammaticalGender {
    /// Neuter grammatical gender
    Neuter = 0b01,

    /// Feminine grammatical gender
    Feminine = 0b10,

    /// Masculine grammatical gender
    Masculine = 0b11,

    /// Grammatical gender not specified
    Any,
}

impl From<u8> for GrammaticalGender {
    fn from(value: u8) -> Self {
        match value & 0b11 {
            0b01 => Self::Neuter,
            0b10 => Self::Feminine,
            0b11 => Self::Masculine,
            _ => Self::Any,
        }
    }
}

impl Display for GrammaticalGender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GrammaticalGender::Any => Ok(()),
            GrammaticalGender::Neuter => write!(f, "neuter"),
            GrammaticalGender::Feminine => write!(f, "feminine"),
            GrammaticalGender::Masculine => write!(f, "masculine"),
        }
    }
}

/// Screen layout configuration
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/native/include/android/configuration.h?fi=ACONFIGURATION_VERSION#372>
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum LayoutDir {
    /// Layout direction: value that corresponds to `ldltr` resource qualifier specified
    Ltr = 0x01 << 6,

    /// Layout direction: value that corresponds to `ldrtl` resource qualifier specified
    Rtl = 0x02 << 6,

    /// Layout direction not specified
    Any(u8),
}

impl From<u8> for LayoutDir {
    fn from(value: u8) -> Self {
        match value & 0xc0 {
            v if v == 0x01 << 6 => Self::Ltr,
            v if v == 0x02 << 6 => Self::Rtl,
            v => Self::Any(v),
        }
    }
}

impl Display for LayoutDir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ltr => write!(f, "ldltr"),
            Self::Rtl => write!(f, "ldrtl"),
            Self::Any(v) => write!(f, "layoutDir={}", v),
        }
    }
}

/// Scren size configuration
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/native/include/android/configuration.h?fi=ACONFIGURATION_VERSION#226>
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum ScreenSize {
    /// Value indicating the screen is at least approximately 320x426 dp units
    Small = 0x01,

    /// Value indicating the screen is at least approximately 320x470 dp units
    Normal = 0x02,

    /// Value indicating the screen is at least approximately 480x640 dp units
    Large = 0x03,

    /// Value indicating the screen is at least approximately 720x960 dp units
    XLarge = 0x04,

    /// Screen size not specified
    Any(u8),
}

impl From<u8> for ScreenSize {
    fn from(value: u8) -> Self {
        match value & 0x0f {
            0x01 => Self::Small,
            0x02 => Self::Normal,
            0x03 => Self::Large,
            0x04 => Self::XLarge,
            v => Self::Any(v),
        }
    }
}

impl Display for ScreenSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Small => write!(f, "small"),
            Self::Normal => write!(f, "normal"),
            Self::Large => write!(f, "large"),
            Self::XLarge => write!(f, "xlarge"),
            Self::Any(v) => write!(f, "screenLayoutSize={}", v),
        }
    }
}

/// Screen variation wide/long
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/native/include/android/configuration.h?fi=ACONFIGURATION_VERSION#257>
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum ScreenLong {
    /// Value that corresponds to the `notlong` resource qualifier
    No = 0x1 << 4,

    /// Value that corresponds to the `long` resource qualifier
    Yes = 0x2 << 4,

    /// Not specified
    Any(u8),
}

impl From<u8> for ScreenLong {
    fn from(value: u8) -> Self {
        match value & 0x30 {
            v if v == 0x1 << 4 => Self::No,
            v if v == 0x2 << 4 => Self::Yes,
            v => Self::Any(v),
        }
    }
}

impl Display for ScreenLong {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::No => write!(f, "notlong"),
            Self::Yes => write!(f, "long"),
            Self::Any(v) => write!(f, "screenLayoutLong={}", v),
        }
    }
}

/// Screen variation round/no
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/native/include/android/configuration.h?fi=ACONFIGURATION_VERSION#272>
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum ScreenRound {
    /// Not round screen
    No = 0x1,

    /// Round screen
    Yes = 0x2,

    /// Not specified
    Any(u8),
}

impl From<u8> for ScreenRound {
    fn from(value: u8) -> Self {
        match value & 0x03 {
            0x1 => Self::No,
            0x2 => Self::Yes,
            v => Self::Any(v),
        }
    }
}

impl Display for ScreenRound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::No => write!(f, "notround"),
            Self::Yes => write!(f, "round"),
            Self::Any(v) => write!(f, "screenRound={}", v),
        }
    }
}

/// Wide color variantions
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/native/include/android/configuration.h?fi=ACONFIGURATION_VERSION#276>
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum WideColorGamut {
    No = 0x1,
    Yes = 0x2,
    Any(u8),
}

impl From<u8> for WideColorGamut {
    fn from(value: u8) -> Self {
        match value & 0x03 {
            0x1 => Self::No,
            0x2 => Self::Yes,
            v => Self::Any(v),
        }
    }
}

impl Display for WideColorGamut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::No => write!(f, "nowidecg"),
            Self::Yes => write!(f, "widecg"),
            Self::Any(v) => write!(f, "wideColorGamut={}", v),
        }
    }
}

/// HDR configuration
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/native/include/android/configuration.h?fi=ACONFIGURATION_VERSION#291>
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum Hdr {
    No = 0x1 << 2,
    Yes = 0x2 << 2,
    Any(u8),
}

impl From<u8> for Hdr {
    fn from(value: u8) -> Self {
        match value & 0x0c {
            v if v == 0x1 << 2 => Self::No,
            v if v == 0x2 << 2 => Self::Yes,
            v => Self::Any(v),
        }
    }
}

impl Display for Hdr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::No => write!(f, "lowdr"),
            Self::Yes => write!(f, "highdr"),
            Self::Any(v) => write!(f, "hdr={}", v),
        }
    }
}

/// Orientation configuration
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/native/include/android/configuration.h?fi=ACONFIGURATION_VERSION#59>
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum Orientation {
    Any = 0x00,
    Port = 0x01,
    Land = 0x02,
    Square = 0x03,

    Unknown(u8),
}

impl From<u8> for Orientation {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Self::Any,
            0x01 => Self::Port,
            0x02 => Self::Land,
            0x03 => Self::Square,
            v => Self::Unknown(v),
        }
    }
}

impl Display for Orientation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Any => Ok(()),
            Self::Port => write!(f, "port"),
            Self::Land => write!(f, "land"),
            Self::Square => write!(f, "square"),
            Self::Unknown(v) => write!(f, "orientation={}", v),
        }
    }
}

/// UI Mode
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/native/include/android/configuration.h?fi=ACONFIGURATION_VERSION#306>
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum UIMode {
    Any = 0x00,
    Normal = 0x01,
    Desk = 0x02,
    Car = 0x03,
    Television = 0x04,
    Appliance = 0x05,
    Watch = 0x06,
    VRHeadset = 0x07,

    Unknown(u8),
}

impl From<u8> for UIMode {
    fn from(value: u8) -> Self {
        match value & 0x0f {
            0x00 => Self::Any,
            0x01 => Self::Normal,
            0x02 => Self::Desk,
            0x03 => Self::Car,
            0x04 => Self::Television,
            0x05 => Self::Appliance,
            0x06 => Self::Watch,
            0x07 => Self::VRHeadset,
            v => Self::Unknown(v),
        }
    }
}

impl Display for UIMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // original code don't handle Normal case, so as we
            Self::Any | Self::Normal => Ok(()),
            Self::Desk => write!(f, "desk"),
            Self::Car => write!(f, "car"),
            Self::Television => write!(f, "television"),
            Self::Appliance => write!(f, "appliance"),
            Self::Watch => write!(f, "watch"),
            Self::VRHeadset => write!(f, "vrheadset"),
            Self::Unknown(v) => write!(f, "uiModeType={}", v),
        }
    }
}

/// UI night mode
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/native/include/android/configuration.h?fi=ACONFIGURATION_VERSION#345>
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum UIModeNight {
    Any = 0x00 << 4,
    No = 0x01 << 4,
    Yes = 0x02 << 4,

    Unknown(u8),
}

impl From<u8> for UIModeNight {
    fn from(value: u8) -> Self {
        match value & 0x30 {
            v if v == 0x00 << 4 => Self::Any,
            v if v == 0x01 << 4 => Self::No,
            v if v == 0x02 << 4 => Self::Yes,
            v => Self::Unknown(v),
        }
    }
}

impl Display for UIModeNight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Any => Ok(()),
            Self::No => f.write_str("notnight"),
            Self::Yes => f.write_str("night"),
            Self::Unknown(v) => write!(f, "uiModeNight={}", v),
        }
    }
}

/// Density value
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/native/include/android/configuration.h?fi=ACONFIGURATION_VERSION#93>
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum Density {
    Default = 0,
    Low = 120,
    Medium = 160,
    TV = 213,
    High = 240,
    XHigh = 320,
    XXHigh = 480,
    XXXHigh = 640,
    Any = 0xfffe,
    None = 0xffff,
    Unknown(u16),
}

impl From<u16> for Density {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::Default,
            120 => Self::Low,
            160 => Self::Medium,
            213 => Self::TV,
            240 => Self::High,
            320 => Self::XHigh,
            480 => Self::XXHigh,
            640 => Self::XXXHigh,
            0xfffe => Self::Any,
            0xffff => Self::None,
            v => Self::Unknown(v),
        }
    }
}

impl From<Density> for u16 {
    fn from(value: Density) -> Self {
        match value {
            Density::Default => 0,
            Density::Low => 120,
            Density::Medium => 160,
            Density::TV => 213,
            Density::High => 240,
            Density::XHigh => 320,
            Density::XXHigh => 480,
            Density::XXXHigh => 640,
            Density::Any => 0xfffe,
            Density::None => 0xffff,
            Density::Unknown(v) => v,
        }
    }
}

impl Display for Density {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Default => Ok(()),
            Self::Low => write!(f, "ldpi"),
            Self::Medium => write!(f, "mdpi"),
            Self::TV => write!(f, "tvdpi"),
            Self::High => write!(f, "hdpi"),
            Self::XHigh => write!(f, "xhdpi"),
            Self::XXHigh => write!(f, "xxhdpi"),
            Self::XXXHigh => write!(f, "xxxhdpi"),
            Self::Any => write!(f, "anydpi"),
            Self::None => write!(f, "nodpi"),
            Self::Unknown(v) => write!(f, "{}dpi", v),
        }
    }
}

/// Touchscreen configuration
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/native/include/android/configuration.h?fi=ACONFIGURATION_VERSION#76>
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum Touchscreen {
    Any = 0x00,
    NoTouch = 0x01,
    Stylus = 0x02,
    Finger = 0x03,
    Unknown(u8),
}

impl From<u8> for Touchscreen {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Self::Any,
            0x01 => Self::NoTouch,
            0x02 => Self::Stylus,
            0x03 => Self::Finger,
            v => Self::Unknown(v),
        }
    }
}

impl Display for Touchscreen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Any => Ok(()),
            Self::NoTouch => write!(f, "notouch"),
            Self::Stylus => write!(f, "stylus"),
            Self::Finger => write!(f, "finger"),
            Self::Unknown(v) => write!(f, "touchscreen={}", v),
        }
    }
}

/// Keyboard availability
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/native/include/android/configuration.h?fi=ACONFIGURATION_VERSION#190>
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum KeysHidden {
    Any = 0x00,
    No = 0x01,
    Yes = 0x02,
    Soft = 0x03,
    Unknown,
}

impl From<u8> for KeysHidden {
    fn from(value: u8) -> Self {
        match value & 0x03 {
            0x00 => Self::Any,
            0x01 => Self::No,
            0x02 => Self::Yes,
            0x03 => Self::Soft,
            _ => Self::Unknown,
        }
    }
}

impl Display for KeysHidden {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::No => write!(f, "keysexposed"),
            Self::Yes => write!(f, "keyshidden"),
            Self::Soft => write!(f, "keyssoft"),
            Self::Any | Self::Unknown => Ok(()),
        }
    }
}

/// Keyboard type
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/native/include/android/configuration.h?fi=ACONFIGURATION_VERSION#142>
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum Keyboard {
    Any = 0x00,
    NoKeys = 0x01,
    Qwerty = 0x02,
    Key12 = 0x03,
    Unknown(u8),
}

impl From<u8> for Keyboard {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Self::Any,
            0x01 => Self::NoKeys,
            0x02 => Self::Qwerty,
            0x03 => Self::Key12,
            v => Self::Unknown(v),
        }
    }
}

impl Display for Keyboard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Any => Ok(()),
            Self::NoKeys => write!(f, "nokeys"),
            Self::Qwerty => write!(f, "qwerty"),
            Self::Key12 => write!(f, "12key"),
            Self::Unknown(v) => write!(f, "keyboard={}", v),
        }
    }
}

/// Navigation availability
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/native/include/android/configuration.h?fi=ACONFIGURATION_VERSION#211>
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum NavHidden {
    Any = 0x00 << 2,
    No = 0x01 << 2,
    Yes = 0x02 << 2,
    Unknown(u8),
}

impl From<u8> for NavHidden {
    fn from(value: u8) -> Self {
        match value & 0x0c {
            v if v == 0x00 << 2 => Self::Any,
            v if v == 0x01 << 2 => Self::No,
            v if v == 0x02 << 2 => Self::Yes,
            v => Self::Unknown(v),
        }
    }
}

impl Display for NavHidden {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Any => Ok(()),
            Self::No => write!(f, "navexposed"),
            Self::Yes => write!(f, "navhidden"),
            Self::Unknown(v) => write!(f, "inputFlagsNavHidden={}", v),
        }
    }
}

/// Navigation type
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/native/include/android/configuration.h?fi=ACONFIGURATION_VERSION#163>
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum Navigation {
    Any = 0x00,
    NoNav = 0x01,
    Dpad = 0x02,
    Trackball = 0x03,
    Wheel = 0x04,
    Unknown(u8),
}

impl From<u8> for Navigation {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Self::Any,
            0x01 => Self::NoNav,
            0x02 => Self::Dpad,
            0x03 => Self::Trackball,
            0x04 => Self::Wheel,
            v => Self::Unknown(v),
        }
    }
}

impl Display for Navigation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Any => Ok(()),
            Self::NoNav => write!(f, "nonav"),
            Self::Dpad => write!(f, "dpad"),
            Self::Trackball => write!(f, "trackball"),
            Self::Wheel => write!(f, "wheel"),
            Self::Unknown(v) => write!(f, "navigation={}", v),
        }
    }
}

/// Describes a particular resource configuration
///
/// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#967>
///
/// Default values (maybe): <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/core/java/android/content/res/Configuration.java#1572>
#[repr(C)]
#[derive(Debug, Default, Eq, Clone, Copy)]
pub struct ResTableConfig {
    /// Number of elements in this structure
    pub size: u32,

    /// **cpp structure**
    /// ```cpp
    /// union {
    ///     struct {
    ///         // Mobile country code (from SIM).  0 means "any".
    ///         uint16_t mcc;
    ///         // Mobile network code (from SIM).  0 means "any".
    ///         uint16_t mnc;
    ///     };
    ///     uint32_t imsi;
    /// };
    /// ```
    pub imsi: u32,

    /// **cpp structure**
    /// ```cpp
    /// union {
    ///     struct {
    ///         // This field can take three different forms:
    ///         // - \0\0 means "any".
    ///         //
    ///         // - Two 7 bit ascii values interpreted as ISO-639-1 language
    ///         //   codes ('fr', 'en' etc. etc.). The high bit for both bytes is
    ///         //   zero.
    ///         //
    ///         // - A single 16 bit little endian packed value representing an
    ///         //   ISO-639-2 3 letter language code. This will be of the form:
    ///         //
    ///         //   {1, t, t, t, t, t, s, s, s, s, s, f, f, f, f, f}
    ///         //
    ///         //   bit[0, 4] = first letter of the language code
    ///         //   bit[5, 9] = second letter of the language code
    ///         //   bit[10, 14] = third letter of the language code.
    ///         //   bit[15] = 1 always
    ///         //
    ///         // For backwards compatibility, languages that have unambiguous
    ///         // two letter codes are represented in that format.
    ///         //
    ///         // The layout is always bigendian irrespective of the runtime
    ///         // architecture.
    ///         char language[2];
    ///
    ///         // This field can take three different forms:
    ///         // - \0\0 means "any".
    ///         //
    ///         // - Two 7 bit ascii values interpreted as 2 letter region
    ///         //   codes ('US', 'GB' etc.). The high bit for both bytes is zero.
    ///         //
    ///         // - An UN M.49 3 digit region code. For simplicity, these are packed
    ///         //   in the same manner as the language codes, though we should need
    ///         //   only 10 bits to represent them, instead of the 15.
    ///         //
    ///         // The layout is always bigendian irrespective of the runtime
    ///         // architecture.
    ///         char country[2];
    ///     };
    ///     uint32_t locale;
    /// };
    /// ```
    pub locale: u32,

    /// **cpp structure**
    /// ```cpp
    /// union {
    ///     struct {
    ///         uint8_t orientation;
    ///         uint8_t touchscreen;
    ///         uint16_t density;
    ///     };
    ///     uint32_t screenType;
    /// };
    /// ```
    pub screen_type: u32,

    /// **cpp structure**
    /// ```cpp
    /// struct {
    ///     union {
    ///         struct {
    ///             uint8_t keyboard;
    ///             uint8_t navigation;
    ///             uint8_t inputFlags;
    ///             uint8_t inputFieldPad0;
    ///         };
    ///         struct {
    ///             uint32_t input : 24;
    ///             uint32_t inputFullPad0 : 8;
    ///         };
    ///         struct {
    ///             uint8_t grammaticalInflectionPad0[3];
    ///             uint8_t grammaticalInflection;
    ///         };
    ///     };
    /// };
    /// ```
    pub generic_purpose_field: u32,

    /// **cpp structure**
    /// ```cpp
    /// union {
    ///     struct {
    ///         uint16_t screenWidth;
    ///         uint16_t screenHeight;
    ///     };
    ///     uint32_t screenSize;
    /// };
    /// ```
    pub screen_size: u32,

    /// **cpp structure**
    /// ```cpp
    /// union {
    ///     struct {
    ///         uint16_t sdkVersion;
    ///         // For now minorVersion must always be 0!!!  Its meaning
    ///         // is currently undefined.
    ///         uint16_t minorVersion;
    ///     };
    ///     uint32_t version;
    /// };
    /// ```
    pub version: u32,

    /// **cpp structure**
    /// ```cpp
    /// union {
    ///     struct {
    ///         uint8_t screenLayout;
    ///         uint8_t uiMode;
    ///         uint16_t smallestScreenWidthDp;
    ///     };
    ///     uint32_t screenConfig;
    /// };
    /// ```
    pub screen_config: u32,

    /// **cpp structure**
    /// ```cpp
    /// union {
    ///     struct {
    ///         uint16_t screenWidthDp;
    ///         uint16_t screenHeightDp;
    ///     };
    ///     uint32_t screenSizeDp;
    /// };
    /// ```
    pub screen_size_dp: u32,

    /// The ISO-15924 short name for the script corresponding to this configuration
    ///
    /// Eg. Hant, Latn, etc.
    ///
    /// Interpreted in conjunction with the locale field
    pub locale_script: [u8; 4],

    /// A single BCP-47 variant subrtag.
    /// Will vary in length between 4 and 8 cahrs
    /// Interpreted in conjunction with the locale field
    pub locale_variant: [u8; 8],

    /// An extension of screenConfig.
    ///
    /// ```cpp
    /// union {
    ///     struct {
    ///         uint8_t screenLayout2;      // Contains round/notround qualifier.
    ///         uint8_t colorMode;          // Wide-gamut, HDR, etc.
    ///         uint16_t screenConfigPad2;  // Reserved padding.
    ///     };
    ///     uint32_t screenConfig2;
    /// };
    /// ```
    pub screen_config_2: u32,

    /// If false and `locale_script` is set, it means that the script of the locale was explicitly provided
    ///
    /// If true, it means that `locale_script` was automatically computed
    pub locale_script_was_computed: bool,

    /// The value of BCP 47 Unicode extension for key `nu` (numbering system)
    /// Varies in length from 3 to 8 chars
    /// Zero filled value
    pub locale_numbering_system: [u8; 8],

    /// Mark all padding explicitly so it's clear how much we can expand it
    pub end_padding: [u8; 3],
}

impl ResTableConfig {
    #[inline(always)]
    pub(crate) fn parse(input: &mut &[u8]) -> ModalResult<ResTableConfig> {
        // to keep track of how many bytes was consumed
        let start = input.len();

        let size = le_u32.parse_next(input)?;

        let mut config = ResTableConfig {
            size,
            ..ResTableConfig::default()
        };

        (le_u32, le_u32, le_u32)
            .map(|(imsi, locale, screen_type)| {
                config.imsi = imsi;
                config.locale = locale;
                config.screen_type = screen_type;
            })
            .parse_next(input)?;

        if size >= 20 {
            config.generic_purpose_field = le_u32.parse_next(input)?;
        }
        if size >= 24 {
            config.screen_size = le_u32.parse_next(input)?;
        }
        if size >= 28 {
            config.version = le_u32.parse_next(input)?;
        }
        if size >= 32 {
            config.screen_config = le_u32.parse_next(input)?;
        }
        if size >= 36 {
            config.screen_size_dp = le_u32.parse_next(input)?;
        }
        if size >= 40 {
            config.locale_script = take(4usize)
                .parse_next(input)?
                .try_into()
                .expect("expected 4 bytes for locale_script");
        }
        if size >= 48 {
            config.locale_variant = take(8usize)
                .parse_next(input)?
                .try_into()
                .expect("expected 8 bytes for locale_variant");
        }
        if size >= 52 {
            config.screen_config_2 = le_u32.parse_next(input)?;
        }
        if size >= 53 {
            config.locale_script_was_computed = u8.parse_next(input)? != 0;
        }
        if size >= 61 {
            config.locale_numbering_system = take(8usize)
                .parse_next(input)?
                .try_into()
                .expect("expected 8 bytes for locale_numbering_system");
        }
        if size >= 64 {
            config.end_padding = take(3usize)
                .parse_next(input)?
                .try_into()
                .expect("expected 3 bytes for end padding");
        }
        if size > 64 {
            warn!("got unexpected ResTable_config structure, please open issue with this file");
        }

        // consume leftover bytes, if any
        let consumed = (start - input.len()) as u32;
        let _ = take(size.saturating_sub(consumed) as usize).parse_next(input)?;

        Ok(config)
    }

    /// Convert [`ResTableConfig::imsi`] to union like field
    #[inline]
    pub fn get_mcc_mnc(&self) -> (u16, u16) {
        let mcc = (self.imsi & 0x0000_FFFF) as u16;
        let mnc = ((self.imsi >> 16) & 0x0000_FFFF) as u16;
        (mcc, mnc)
    }

    /// Convert [`ResTableConfig::screen_type`] to union like
    pub fn get_orientation_touchscreen_density(&self) -> (u8, u8, u16) {
        let orientation = (self.screen_type & 0x0000_00FF) as u8;
        let touchscreen = ((self.screen_type >> 8) & 0x0000_00FF) as u8;
        let density = ((self.screen_type >> 16) & 0x0000_FFFF) as u16;
        (orientation, touchscreen, density)
    }

    /// Set config density
    #[inline]
    pub fn set_density(&mut self, density: Density) {
        self.screen_type =
            (self.screen_type & 0x0000_FFFF) | ((u32::from(u16::from(density))) << 16);
    }

    /// Extracts `keyboard`, `navigation`, and `inputFlags`
    pub fn get_keyboard_navigation_input_flags(&self) -> (u8, u8, u8) {
        let keyboard = (self.generic_purpose_field & 0x0000_00FF) as u8;
        let navigation = ((self.generic_purpose_field >> 8) & 0x0000_00FF) as u8;
        let input_flags = ((self.generic_purpose_field >> 16) & 0x0000_00FF) as u8;
        (keyboard, navigation, input_flags)
    }

    /// Extracts the 24-bit `input` value
    #[inline]
    pub fn get_input(&self) -> u32 {
        self.generic_purpose_field & 0x00FF_FFFF
    }

    /// Extracts the 8-bit `grammaticalInflection`
    #[inline]
    pub fn get_grammatical_inflection(&self) -> u8 {
        ((self.generic_purpose_field >> 24) & 0xFF) as u8
    }

    pub fn get_screen_width_height(&self) -> (u16, u16) {
        let screen_width = (self.screen_size & 0x0000_FFFF) as u16;
        let screen_height = ((self.screen_size >> 16) & 0x0000_FFFF) as u16;
        (screen_width, screen_height)
    }

    pub fn get_sdk_minor_version(&self) -> (u16, u16) {
        let sdk_version = (self.version & 0x0000_FFFF) as u16;
        let minor_version = ((self.version >> 16) & 0x0000_FFFF) as u16;
        (sdk_version, minor_version)
    }

    pub fn get_screen_layout_ui_smallest_width(&self) -> (u8, u8, u16) {
        let screen_layout = (self.screen_config & 0x0000_00FF) as u8;
        let ui_mode = ((self.screen_config >> 8) & 0x0000_00FF) as u8;
        let smallest_screen_width_dp = ((self.screen_config >> 16) & 0x0000_FFFF) as u16;
        (screen_layout, ui_mode, smallest_screen_width_dp)
    }

    pub fn get_screen_width_height_dp(&self) -> (u16, u16) {
        let screen_width_dp = (self.screen_size_dp & 0x0000_FFFF) as u16;
        let screen_height_dp = ((self.screen_size_dp >> 16) & 0x0000_FFFF) as u16;
        (screen_width_dp, screen_height_dp)
    }

    pub fn get_screen_layout_2_color_mode(&self) -> (u8, u8) {
        let screen_layout2 = (self.screen_config_2 & 0x0000_00FF) as u8;
        let color_mode = ((self.screen_config_2 >> 8) & 0x0000_00FF) as u8;
        // NOTE: reserved padding, maybe sometimes in the future will be used
        // let screen_config_pad2 = ((self.screen_config_2 >> 16) & 0x0000_FFFF) as u16;

        (screen_layout2, color_mode)
    }

    fn unpack_language(&self, input: [u8; 2]) -> String {
        let (_, buf) = self.unpack_language_or_region(input, b'a');

        std::str::from_utf8(&buf)
            .expect("can't decode language from given configuration")
            .trim_end_matches('\0')
            .to_owned()
    }

    fn unpack_region(&self, input: [u8; 2]) -> String {
        let (_, buf) = self.unpack_language_or_region(input, b'0');

        std::str::from_utf8(&buf)
            .expect("can't decode region from given configuration")
            .trim_end_matches('\0')
            .to_owned()
    }

    /// Decode language or region
    ///
    /// [Source Code](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/libs/androidfw/ResourceTypes.cpp;drc=61197364367c9e404c7da6900658f1b16c42d0da;l=2044)
    fn unpack_language_or_region(&self, input: [u8; 2], base: u8) -> (usize, [u8; 4]) {
        let mut out = [0u8; 4];

        if (input[0] & 0x80) != 0 {
            // The high bit is "1", which means this is a packed three letter language code.

            // The smallest 5 bits of the second char are the first alphabet.
            let first = input[1] & 0x1f;

            // The last three bits of the second char and the first two bits of the first char are the second alphabet.
            let second = ((input[1] & 0xe0) >> 5) + ((input[0] & 0x03) << 3);

            // Bits 3 to 7 (inclusive) of the first char are the third alphabet.
            let third = (input[0] & 0x7c) >> 2;

            out[0] = first + base;
            out[1] = second + base;
            out[2] = third + base;
            out[3] = 0;
            (3, out)
        } else if input[0] != 0 {
            out[0] = input[0];
            out[1] = input[1];
            (2, out)
        } else {
            (0, out)
        }
    }

    /// Decode locale field to readable string
    ///
    /// [Source Code](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/libs/androidfw/ResourceTypes.cpp;l=3101;drc=61197364367c9e404c7da6900658f1b16c42d0da;bpv=0;bpt=1)
    fn append_dir_locale(&self, result: &mut String) {
        let bytes = self.locale.to_le_bytes();
        let language = [bytes[0], bytes[1]];
        let country = [bytes[2], bytes[3]];

        if language[0] == 0 {
            return;
        }

        let script_was_provided = self.locale_script[0] != 0 && !self.locale_script_was_computed;
        let has_variant = self.locale_variant[0] != 0;
        let has_numbering_system = self.locale_numbering_system[0] != 0;

        // legacy format
        if !script_was_provided && !has_variant && !has_numbering_system {
            if !result.is_empty() {
                result.push('-');
            }

            let unpacked_language = self.unpack_language(language);
            result.push_str(&unpacked_language);

            if country[0] != 0 {
                result.push_str("-r");

                let unpacked_region = self.unpack_region(country);
                result.push_str(&unpacked_region);
            }

            return;
        }

        // new format (modified BCP 47 tag)
        if !result.is_empty() {
            result.push('-');
        }
        result.push_str("b+");

        let unpacked_language = self.unpack_language(language);
        result.push_str(&unpacked_language);

        if script_was_provided {
            result.push('+');
            let script = std::str::from_utf8(&self.locale_script)
                .expect("can't decode locale_script from given configuration")
                .trim_end_matches('\0');
            result.push_str(script);
        }

        if country[0] != 0 {
            result.push('+');
            let unpacked_region = self.unpack_region(country);
            result.push_str(&unpacked_region);
        }

        if has_variant {
            result.push('+');
            let variant = std::str::from_utf8(&self.locale_variant)
                .expect("can't decode locale_variant from given configuration")
                .trim_end_matches('\0');
            result.push_str(variant);
        }

        if has_numbering_system {
            result.push_str("+u+nu+");
            let numsys = std::str::from_utf8(&self.locale_numbering_system)
                .expect("can't decode locale_numbering_system from given configuration")
                .trim_end_matches('\0');
            result.push_str(numsys);
        }
    }

    /// Represent resource config as readable string
    ///
    /// See: <https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/libs/androidfw/ResourceTypes.cpp#3358>
    ///
    /// App resource overview [Table 2]: <https://developer.android.com/guide/topics/resources/providing-resources#AlternativeResources>
    pub fn as_string(&self) -> String {
        // preallocate some buffer just in case, maybe bad idea
        let mut result = String::with_capacity(self.size as usize);

        let (mcc, mnc) = self.get_mcc_mnc();
        if mcc != 0 {
            let _ = write!(result, "mcc{}", mcc);
        }
        if mnc != 0 {
            if !result.is_empty() {
                result.push('-');
            }
            let _ = write!(result, "mnc{}", mnc);
        }

        self.append_dir_locale(&mut result);

        let gender = GrammaticalGender::from(self.get_grammatical_inflection());
        if !matches!(gender, GrammaticalGender::Any) {
            if !result.is_empty() {
                result.push('-');
            }
            result.push_str(&gender.to_string());
        }

        let (screen_layout, ui_mode, smallest_screen_width_dp) =
            self.get_screen_layout_ui_smallest_width();

        let layout_dir = LayoutDir::from(screen_layout);
        if !matches!(layout_dir, LayoutDir::Any(_)) {
            if !result.is_empty() {
                result.push('-');
            }
            result.push_str(&layout_dir.to_string());
        }

        if smallest_screen_width_dp != 0 {
            if !result.is_empty() {
                result.push('-');
            }

            let _ = write!(result, "sw{}dp", smallest_screen_width_dp);
        }

        let (screen_width_dp, screen_heigh_dp) = self.get_screen_width_height_dp();
        if screen_width_dp != 0 {
            if !result.is_empty() {
                result.push('-');
            }

            let _ = write!(result, "w{}dp", screen_width_dp);
        }
        if screen_heigh_dp != 0 {
            if !result.is_empty() {
                result.push('-');
            }

            let _ = write!(result, "h{}dp", screen_heigh_dp);
        }

        let screensize = ScreenSize::from(screen_layout);
        if !matches!(screensize, ScreenSize::Any(_)) {
            if !result.is_empty() {
                result.push('-');
            }
            result.push_str(&screensize.to_string());
        }

        let screenlong = ScreenLong::from(screen_layout);
        if !matches!(screenlong, ScreenLong::Any(_)) {
            if !result.is_empty() {
                result.push('-');
            }
            result.push_str(&screenlong.to_string());
        }

        let screenround = ScreenRound::from(screen_layout);
        if !matches!(screenround, ScreenRound::Any(_)) {
            if !result.is_empty() {
                result.push('-');
            }
            result.push_str(&screenround.to_string());
        }

        let (_, color_mode) = self.get_screen_layout_2_color_mode();
        let wide_color_gamut = WideColorGamut::from(color_mode);
        if !matches!(wide_color_gamut, WideColorGamut::Any(_)) {
            if !result.is_empty() {
                result.push('-');
            }
            result.push_str(&wide_color_gamut.to_string());
        }

        let hdr = Hdr::from(color_mode);
        if !matches!(hdr, Hdr::Any(_)) {
            if !result.is_empty() {
                result.push('-');
            }
            result.push_str(&hdr.to_string());
        }

        let (orientation, touchscreen, density) = self.get_orientation_touchscreen_density();
        let orientation = Orientation::from(orientation);
        if !matches!(orientation, Orientation::Any) {
            if !result.is_empty() {
                result.push('-');
            }
            result.push_str(&orientation.to_string());
        }

        let ui_mode_type = UIMode::from(ui_mode);
        if !matches!(ui_mode_type, UIMode::Any) {
            if !result.is_empty() {
                result.push('-');
            }
            result.push_str(&ui_mode_type.to_string());
        }

        let ui_mode_night = UIModeNight::from(ui_mode);
        if !matches!(ui_mode_night, UIModeNight::Any) {
            if !result.is_empty() {
                result.push('-');
            }
            result.push_str(&ui_mode_night.to_string());
        }

        let density = Density::from(density);
        if !matches!(density, Density::Default) {
            if !result.is_empty() {
                result.push('-');
            }
            result.push_str(&density.to_string());
        }

        let touchscreen = Touchscreen::from(touchscreen);
        if !matches!(touchscreen, Touchscreen::Any) {
            if !result.is_empty() {
                result.push('-');
            }
            result.push_str(&touchscreen.to_string());
        }

        let (keyboard, navigation, input_flags) = self.get_keyboard_navigation_input_flags();

        let keyshidden = KeysHidden::from(input_flags);
        if !matches!(keyshidden, KeysHidden::Any) {
            if !result.is_empty() {
                result.push('-');
            }
            result.push_str(&keyshidden.to_string());
        }

        let keyboard = Keyboard::from(keyboard);
        if !matches!(keyboard, Keyboard::Any) {
            if !result.is_empty() {
                result.push('-');
            }
            result.push_str(&keyboard.to_string());
        }

        let navhidden = NavHidden::from(input_flags);
        if !matches!(navhidden, NavHidden::Any) {
            if !result.is_empty() {
                result.push('-');
            }
            result.push_str(&navhidden.to_string());
        }

        let navigation = Navigation::from(navigation);
        if !matches!(navigation, Navigation::Any) {
            if !result.is_empty() {
                result.push('-');
            }
            result.push_str(&navigation.to_string());
        }

        if self.screen_size != 0 {
            if !result.is_empty() {
                result.push('-');
            }
            let (screen_width, screen_height) = self.get_screen_width_height();

            let _ = write!(result, "{}x{}", screen_width, screen_height);
        }

        if self.version != 0 {
            if !result.is_empty() {
                result.push('-');
            }

            let (sdk_version, minor_version) = self.get_sdk_minor_version();
            let _ = write!(result, "v{}", sdk_version);
            if minor_version != 0 {
                let _ = write!(result, ".{}", minor_version);
            }
        }

        result
    }
}

impl Hash for ResTableConfig {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.imsi.hash(state);
        self.locale.hash(state);
        self.screen_type.hash(state);
        self.generic_purpose_field.hash(state);
        self.screen_size.hash(state);
        self.version.hash(state);
        self.screen_config.hash(state);
        self.screen_size_dp.hash(state);
        self.locale_script.hash(state);
        self.locale_variant.hash(state);
        self.screen_config_2.hash(state);
        self.locale_script_was_computed.hash(state);
        self.locale_numbering_system.hash(state);
        self.end_padding.hash(state);
    }
}

impl PartialEq for ResTableConfig {
    fn eq(&self, other: &Self) -> bool {
        self.imsi == other.imsi
            && self.locale == other.locale
            && self.screen_type == other.screen_type
            && self.generic_purpose_field == other.generic_purpose_field
            && self.screen_size == other.screen_size
            && self.version == other.version
            && self.screen_config == other.screen_config
            && self.screen_size_dp == other.screen_size_dp
            && self.locale_script == other.locale_script
            && self.locale_variant == other.locale_variant
            && self.screen_config_2 == other.screen_config_2
            && self.locale_script_was_computed == other.locale_script_was_computed
            && self.locale_numbering_system == other.locale_numbering_system
            && self.end_padding == other.end_padding
    }
}

impl PartialOrd for ResTableConfig {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ResTableConfig {
    fn cmp(&self, other: &Self) -> Ordering {
        self.imsi
            .cmp(&other.imsi)
            .then_with(|| self.locale.cmp(&other.locale))
            .then_with(|| self.screen_type.cmp(&other.screen_type))
            .then_with(|| self.generic_purpose_field.cmp(&other.generic_purpose_field))
            .then_with(|| self.screen_size.cmp(&other.screen_size))
            .then_with(|| self.version.cmp(&other.version))
            .then_with(|| self.screen_config.cmp(&other.screen_config))
            .then_with(|| self.screen_size_dp.cmp(&other.screen_size_dp))
            .then_with(|| self.locale_script.cmp(&other.locale_script))
            .then_with(|| self.locale_variant.cmp(&other.locale_variant))
            .then_with(|| self.screen_config_2.cmp(&other.screen_config_2))
            .then_with(|| {
                self.locale_script_was_computed
                    .cmp(&other.locale_script_was_computed)
            })
            .then_with(|| {
                self.locale_numbering_system
                    .cmp(&other.locale_numbering_system)
            })
            .then_with(|| self.end_padding.cmp(&other.end_padding))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn p32(s: &str) -> u32 {
        assert!(s.len() <= 4, "expected str length between 0 and 4 symbols");

        s.bytes().fold(0u32, |acc, b| (acc << 8) | b as u32)
    }

    #[test]
    fn test_mcc_mnc_1() {
        let mut config = ResTableConfig::default();

        config.imsi = p32("\x00\x14\x01\x4e");
        let (mcc, mnc) = config.get_mcc_mnc();

        assert_eq!(mcc, 334);
        assert_eq!(mnc, 20);

        assert_eq!("mcc334-mnc20", config.as_string())
    }

    #[test]
    fn test_mcc_mnc_2() {
        let mut config = ResTableConfig::default();

        config.imsi = p32("\x00\x01\x00\x01");
        let (mcc, mnc) = config.get_mcc_mnc();

        assert_eq!(mcc, 1);
        assert_eq!(mnc, 1);

        assert_eq!("mcc1-mnc1", config.as_string())
    }

    #[test]
    fn test_config_density() {
        let mut config = ResTableConfig::default();
        config.set_density(Density::Low);
        assert_eq!("ldpi", config.as_string());

        config.set_density(Density::XXXHigh);
        assert_eq!("xxxhdpi", config.as_string());

        config.set_density(Density::Unknown(123));
        assert_eq!("123dpi", config.as_string());
    }
}
