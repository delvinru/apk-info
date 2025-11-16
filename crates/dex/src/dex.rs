use std::borrow::Cow;
use std::sync::Arc;

use bitflags::bitflags;
use winnow::binary::{be_u16, be_u32, le_u16, le_u32, u8};
use winnow::combinator::repeat;
use winnow::error::{ContextError, ErrMode};
use winnow::prelude::*;
use winnow::token::take;

use crate::errors::DexError;

/// The constant is used to indicate the endiannes of the file in whic it is found.
///
/// This constant means - little-endian.
///
/// See: <https://source.android.com/docs/core/runtime/dex-format#endian-constant>
pub const ENDIAN_CONSTANT: u32 = 0x12345678;

/// The constant is used to indicate the endiannes of the file in whic it is found.
///
/// This constant means - big-endian.
///
/// See: <https://source.android.com/docs/core/runtime/dex-format#endian-constant>
pub const REVERSE_ENDIAN_CONSTANT: u32 = 0x78563412;

/// The constant is used to indicate that an index value is absent.
///
/// See: <https://source.android.com/docs/core/runtime/dex-format#no-index>
pub const NO_INDEX: u32 = u32::MAX;

#[derive(Debug)]
pub struct Dex {
    /// Store data of dex file inside this structure
    data: Vec<u8>,

    /// Information about dex header
    pub header: DexHeader,

    /// Dex strings
    pub string_ids: Vec<u32>,

    /// Dex types
    pub type_ids: Vec<u32>,

    /// Dex prototype items
    pub proto_ids: Vec<ProtoItem>,

    /// Dex field items
    pub field_ids: Vec<FieldItem>,

    /// Dex method items
    pub method_ids: Vec<MethodItem>,

    /// Dex class items
    pub class_defs: Vec<ClassItem>,

    /// Dex map list
    pub map_list: Vec<MapItem>,
}

impl Dex {
    /// Parse given dex file
    ///
    /// ```ignore
    /// let dex = Dex::new(data).expect("can't parse dex file");
    /// ```
    pub fn new(data: Vec<u8>) -> Result<Dex, DexError> {
        let input = &mut &data[..];

        let header = Self::parse_dex_header(input).map_err(|_| DexError::InvalidHeader)?;

        // TODO: need somehow validate this `count` values
        // TODO: consume input for each offset

        let string_ids = repeat(header.string_ids_size as usize, le_u32)
            .parse_next(input)
            .map_err(|_: ContextError| DexError::StringError)?;

        let type_ids = repeat(header.type_ids_size as usize, le_u32)
            .parse_next(input)
            .map_err(|_: ContextError| DexError::TypeError)?;

        let proto_ids = repeat(header.proto_ids_size as usize, ProtoItem::parse)
            .parse_next(input)
            .map_err(|_| DexError::ProtoError)?;

        let field_ids = repeat(header.field_ids_size as usize, FieldItem::parse)
            .parse_next(input)
            .map_err(|_| DexError::FieldError)?;

        let method_ids = repeat(header.method_ids_size as usize, MethodItem::parse)
            .parse_next(input)
            .map_err(|_| DexError::MethodError)?;

        let class_defs = repeat(header.class_defs_size as usize, ClassItem::parse)
            .parse_next(input)
            .map_err(|_| DexError::ClassError)?;

        let map_list = Self::parse_map_items(&data, &header).map_err(|_| DexError::MapListError)?;

        Ok(Dex {
            data,
            header,
            string_ids,
            type_ids,
            proto_ids,
            field_ids,
            method_ids,
            class_defs,
            map_list,
        })
    }

    fn parse_dex_header(input: &mut &[u8]) -> ModalResult<DexHeader> {
        let (magic, _, version, _) = (
            be_u32.verify(|magic| *magic == 0x6465780A),
            u8.verify(|v| *v == 0x30),
            be_u16.try_map(DexVersion::try_from),
            u8.verify(|v| *v == 0x00),
        )
            .parse_next(input)?;

        let (
            checksum,
            signature,
            file_size,
            header_size,
            endian_tag,
            link_size,
            link_off,
            map_off,
            string_ids_size,
            string_ids_off,
            type_ids_size,
            type_ids_off,
            proto_ids_size,
            proto_ids_off,
            field_ids_size,
            field_ids_off,
            method_ids_size,
            method_ids_off,
            class_defs_size,
            class_defs_off,
            data_size,
            data_off,
        ) = (
            le_u32,                                                                         // checksum
            take(20usize).map(Arc::from), // signature
            le_u32,                       // file_size
            le_u32,                       // header_size
            le_u32.verify(|&tag| tag == ENDIAN_CONSTANT || tag == REVERSE_ENDIAN_CONSTANT), // endian_tag
            le_u32,                                         // link_size
            le_u32,                                         // link_off
            le_u32,                                         // map_off
            le_u32,                                         // string_ids_size
            le_u32,                                         // string_ids_off
            le_u32.verify(|&size| size <= u16::MAX.into()), // type_ids_size
            le_u32,                                         // type_ids_off
            le_u32.verify(|&size| size <= u16::MAX.into()), // proto_ids_size
            le_u32,                                         // proto_ids_off
            le_u32,                                         // field_ids_size
            le_u32,                                         // field_ids_off
            le_u32,                                         // method_ids_size
            le_u32,                                         // method_ids_off
            le_u32,                                         // class_defs_size
            le_u32,                                         // class_defs_off
            le_u32,                                         // data_size
            le_u32,                                         // data_off
        )
            .parse_next(input)?;

        let mut container_size = 0;
        let mut header_offset = 0;
        if version >= DexVersion::DEX41 {
            (container_size, header_offset) = (le_u32, le_u32).parse_next(input)?;
        }

        Ok(DexHeader {
            magic,
            version,
            checksum,
            signature,
            file_size,
            header_size,
            endian_tag,
            link_size,
            link_off,
            map_off,
            string_ids_size,
            string_ids_off,
            type_ids_size,
            type_ids_off,
            proto_ids_size,
            proto_ids_off,
            field_ids_size,
            field_ids_off,
            method_ids_size,
            method_ids_off,
            class_defs_size,
            class_defs_off,
            data_size,
            data_off,
            container_size,
            header_offset,
        })
    }

    fn parse_map_items(data: &[u8], header: &DexHeader) -> ModalResult<Vec<MapItem>> {
        let mut input = match data.get(header.map_off as usize..) {
            Some(v) => v,
            None => return Ok(Vec::new()),
        };

        let size = le_u32.parse_next(&mut input)?;
        repeat(size as usize, MapItem::parse).parse_next(&mut input)
    }

    pub fn get_string(&self, idx: usize) -> Option<Cow<'_, str>> {
        let offset = *self.string_ids.get(idx)? as usize;
        let mut data = self.data.get(offset..)?;

        let utf16size = Self::uleb128(&mut data).ok()?;
        let bytes = take::<usize, &[u8], ContextError>(utf16size as usize)
            .parse_next(&mut data)
            .ok()?;

        Some(simd_cesu8::mutf8::decode_lossy(bytes))
    }

    #[inline]
    fn uleb128(input: &mut &[u8]) -> ModalResult<u64> {
        let mut val = 0u64;
        let mut shift = 0u32;

        let mut byte: u8;

        loop {
            byte = u8.parse_next(input)?;
            let b = (byte & 0x7f) as u64;
            val |= b
                .checked_shl(shift)
                .ok_or(ErrMode::Cut(ContextError::new()))?;

            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }

        Ok(val)
    }

    #[inline]
    pub fn get_type(&self, idx: usize) -> Option<Cow<'_, str>> {
        let idx = *self.type_ids.get(idx)?;
        self.get_string(idx as usize)
    }
}

/// Known dex versions
///
/// See: <https://source.android.com/docs/core/runtime/dex-format#dex-file-magic>
#[derive(Default, Debug, Clone, PartialEq, PartialOrd)]
pub enum DexVersion {
    #[default]
    DEX35,
    DEX36,
    DEX37,
    DEX38,
    DEX39,
    DEX40,
    DEX41,
}

impl TryFrom<u16> for DexVersion {
    type Error = DexError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x3335 => Ok(DexVersion::DEX35),
            0x3336 => Ok(DexVersion::DEX36),
            0x3337 => Ok(DexVersion::DEX37),
            0x3338 => Ok(DexVersion::DEX38),
            0x3339 => Ok(DexVersion::DEX39),
            0x3430 => Ok(DexVersion::DEX40),
            0x3431 => Ok(DexVersion::DEX41),
            _ => Err(DexError::UnknownVersion(value)),
        }
    }
}

impl From<DexVersion> for u32 {
    fn from(value: DexVersion) -> Self {
        match value {
            DexVersion::DEX35 => 35,
            DexVersion::DEX36 => 36,
            DexVersion::DEX37 => 37,
            DexVersion::DEX38 => 38,
            DexVersion::DEX39 => 39,
            DexVersion::DEX40 => 40,
            DexVersion::DEX41 => 41,
        }
    }
}

/// Abstraction over dex header
///
/// See: <https://source.android.com/docs/core/runtime/dex-format#header-item>
#[derive(Default, Debug, Clone)]
pub struct DexHeader {
    /// Magic value
    pub magic: u32,

    /// Known dex version
    pub version: DexVersion,

    /// Adler32 checksum of the file
    ///
    /// Used to detect file corruption
    pub checksum: u32,

    /// SHA-1 signature of the file
    ///
    /// Used to uniquely identify files
    pub signature: Arc<[u8]>,

    /// Size of the entire file (including the header) in bytes
    pub file_size: u32,

    /// Size of the header (this entire section) in bytes
    pub header_size: u32,

    /// Endiannes tag - [Dex::ENDIAN_CONSTANT] or [Dex::REVERSE_ENDIAN_CONSTANT]
    pub endian_tag: u32,

    /// Size of the link section
    ///
    /// 0 - if this file isn't statically linked
    pub link_size: u32,

    /// Offset from the start of the file to the link section
    ///
    /// 0 - if `link_size == 0`
    pub link_off: u32,

    /// Offset from the start of the file to the map item
    pub map_off: u32,

    /// Count of strings in the string identifiers list
    pub string_ids_size: u32,

    /// Offset from the start of the file to the string identifiers list
    ///
    /// 0 - if `string_ids_size == 0`
    pub string_ids_off: u32,

    /// Count of elements in the type identifiers list, at most 65535
    pub type_ids_size: u32,

    /// Offset from the start of the file to the type identifiers list
    ///
    /// 0 - if `type_ids_size == 0`
    pub type_ids_off: u32,

    /// Count of elements in the prototype identifiers list, at most 65535
    pub proto_ids_size: u32,

    /// Offset from the start of the file to the prototype identifiers list
    ///
    /// 0 - if `proto_ids_size == 0`
    pub proto_ids_off: u32,

    /// Count of elements in the field identifiers list
    pub field_ids_size: u32,

    /// Offset from the start of the file to the field identifiers list
    ///
    /// 0 - if `field_ids_size == 0`
    pub field_ids_off: u32,

    /// Count of elements in the method identifiers list
    pub method_ids_size: u32,

    /// Offset from the start of the file to the method identifiers list
    ///
    /// 0 - if `method_ids_size == 0`
    pub method_ids_off: u32,

    /// Count of elements in the class definitions list
    pub class_defs_size: u32,

    /// Offset from the start of the file to the class definitions list
    ///
    /// 0 - if `class_defs_size == 0`
    pub class_defs_off: u32,

    /// Size of `data` section in bytes.
    ///
    /// Must be an event multiple of sizeof(uint)
    ///
    /// Unused in [DexVersion::DEX41] or later
    pub data_size: u32,

    /// Offset from the start of the file to the start of the `data` section
    ///
    /// Must be an event multiple of sizeof(uint)
    ///
    /// Unused in [DexVersion::DEX41] or later
    pub data_off: u32,

    /// Size of the entire file (including other dex headers and their data)
    ///
    /// Unused in [DexVersion::DEX40] or earlier
    pub container_size: u32,

    /// Offset from the start of the file to the start of this header
    ///
    /// Unused in [DexVersion::DEX40] or earlier
    pub header_offset: u32,
}

/// Abstraction over `proto_id_item`
///
/// See: <https://source.android.com/docs/core/runtime/dex-format#proto-id-item>
#[derive(Debug)]
pub struct ProtoItem {
    /// Index into the [Dex::string_ids] list for the short-form descriptor string of this prototype
    pub shorty_idx: u32,

    /// Index into the [Dex::type_ids] list for the return type of this prototype
    pub return_type_idx: u32,

    /// Offset from the start of the file to the list of parameter types for this prototype
    ///
    /// 0 - if this prototype has no parameters
    pub parameters_off: u32,
}

impl ProtoItem {
    #[inline]
    fn parse(input: &mut &[u8]) -> ModalResult<ProtoItem> {
        (le_u32, le_u32, le_u32)
            .map(|(shorty_idx, return_type_idx, parameters_off)| ProtoItem {
                shorty_idx,
                return_type_idx,
                parameters_off,
            })
            .parse_next(input)
    }

    pub fn view<'a>(&'a self, dex: &'a Dex) -> ProtoView<'a> {
        ProtoView { proto: self, dex }
    }
}

/// Nice way to access fields from [ProtoItem]
pub struct ProtoView<'a> {
    proto: &'a ProtoItem,
    dex: &'a Dex,
}

impl<'a> ProtoView<'a> {
    /// Get descriptor of this prototype from strings pool
    #[inline]
    pub fn descriptor(&self) -> Option<Cow<'_, str>> {
        self.dex.get_string(self.proto.shorty_idx as usize)
    }

    /// Get return type of this prototype from types pool
    pub fn return_type(&self) -> Option<Cow<'_, str>> {
        self.dex.get_type(self.proto.return_type_idx as usize)
    }
}

/// Abstraction over `field_id_item`
///
/// See: <https://source.android.com/docs/core/runtime/dex-format#field-id-item>
#[derive(Debug)]
pub struct FieldItem {
    /// Index into the [Dex::type_ids] list for the definer of this field
    pub class_idx: u16,

    /// Index into the [Dex::type_ids] list for the type of this field
    pub type_idx: u16,

    /// Index into the [Dex::string_ids] list for the name of this field
    pub name_idx: u32,
}

impl FieldItem {
    #[inline]
    fn parse(input: &mut &[u8]) -> ModalResult<FieldItem> {
        (le_u16, le_u16, le_u32)
            .map(|(class_idx, type_idx, name_idx)| FieldItem {
                class_idx,
                type_idx,
                name_idx,
            })
            .parse_next(input)
    }

    /// Get field class
    #[inline]
    pub fn get_class<'a>(&'a self, dex: &'a Dex) -> Option<Cow<'a, str>> {
        dex.get_type(self.class_idx as usize)
    }

    /// Get field type
    #[inline]
    pub fn get_type<'a>(&'a self, dex: &'a Dex) -> Option<Cow<'a, str>> {
        dex.get_type(self.type_idx as usize)
    }

    /// Get field name
    #[inline]
    pub fn get_name<'a>(&'a self, dex: &'a Dex) -> Option<Cow<'a, str>> {
        dex.get_string(self.name_idx as usize)
    }
}

/// Abstraction over `method_id_item`
///
/// See: <https://source.android.com/docs/core/runtime/dex-format#method-id-item>
#[derive(Debug)]
pub struct MethodItem {
    /// Index into the [Dex::type_ids] list for the definer of this method
    pub class_idx: u16,

    /// Index into the [Dex::proto_ids] list for the prototype of this method
    pub proto_idx: u16,

    /// Index into the [Dex::string_ids] list for the name of this method
    pub name_idx: u32,
}

impl MethodItem {
    #[inline]
    fn parse(input: &mut &[u8]) -> ModalResult<MethodItem> {
        (le_u16, le_u16, le_u32)
            .map(|(class_idx, proto_idx, name_idx)| MethodItem {
                class_idx,
                proto_idx,
                name_idx,
            })
            .parse_next(input)
    }

    /// Get method class name
    #[inline]
    pub fn get_class<'a>(&'a self, dex: &'a Dex) -> Option<Cow<'a, str>> {
        dex.get_type(self.class_idx as usize)
    }

    /// Get method prototype
    #[inline]
    pub fn get_prototype<'a>(&'a self, dex: &'a Dex) -> Option<&'a ProtoItem> {
        dex.proto_ids.get(self.proto_idx as usize)
    }

    /// Get method name
    #[inline]
    pub fn get_name<'a>(&'a self, dex: &'a Dex) -> Option<Cow<'a, str>> {
        dex.get_string(self.name_idx as usize)
    }
}

/// Abstraction over `class_def_item`
///
/// See: <https://source.android.com/docs/core/runtime/dex-format#class-def-item>
#[derive(Debug)]
pub struct ClassItem {
    /// Index into the [Dex::type_ids] list for this class
    pub class_idx: u32,

    /// Access flags for the class
    pub access_flags: AccessFlags,

    /// Index into the [Dex::type_ids] list for the superclass
    ///
    /// [NO_INDEX] - if this class has no superclass  (i.e., it is a root class such as `Object`)
    pub superclass_idx: u32,

    /// Offset from the start of the file to the list of interfaces
    ///
    /// `0` - if there are none
    pub interfaces_off: u32,

    /// Index into the [Dex::string_ids] list for the name of the file containing
    /// the original source for (at least most of) this class
    ///
    /// [NO_INDEX] - lack of this information
    pub source_file_idx: u32,

    /// Offset from the start of the file to the annotations structure for this class
    ///
    /// `0` - if there are no annotations on this class
    pub annotations_off: u32,

    /// Offset from the start of the file to the associated class data for this item
    ///
    /// `0` - if there is no class data for this class
    pub class_data_off: u32,

    /// Offset from the start of the file to the list of initial values for `static` fields
    ///
    /// `0` - if there are none (and all `static` fields are to be initialized with `0` or `null`)
    pub static_values_off: u32,
}

impl ClassItem {
    #[inline]
    fn parse(input: &mut &[u8]) -> ModalResult<ClassItem> {
        (
            le_u32,
            le_u32.map(AccessFlags::from_bits_truncate),
            le_u32,
            le_u32,
            le_u32,
            le_u32,
            le_u32,
            le_u32,
        )
            .map(
                |(
                    class_idx,
                    access_flags,
                    superclass_idx,
                    interfaces_off,
                    source_file_idx,
                    annotations_off,
                    class_data_off,
                    static_values_off,
                )| ClassItem {
                    class_idx,
                    access_flags,
                    superclass_idx,
                    interfaces_off,
                    source_file_idx,
                    annotations_off,
                    class_data_off,
                    static_values_off,
                },
            )
            .parse_next(input)
    }

    /// Get class name
    #[inline]
    pub fn get_name<'a>(&'a self, dex: &'a Dex) -> Option<Cow<'a, str>> {
        dex.get_type(self.class_idx as usize)
    }

    /// Get superclass for this class
    #[inline]
    pub fn get_superclass<'a>(&'a self, dex: &'a Dex) -> Option<Cow<'a, str>> {
        if self.superclass_idx == NO_INDEX {
            return None;
        }

        dex.get_type(self.superclass_idx as usize)
    }

    /// Get source file for this class
    #[inline]
    pub fn get_source_file<'a>(&'a self, dex: &'a Dex) -> Option<Cow<'a, str>> {
        if self.source_file_idx == NO_INDEX {
            return None;
        }

        dex.get_string(self.source_file_idx as usize)
    }
}

bitflags! {
    /// Represents the access flags used in Android class files for classes, fields, and methods.
    ///
    /// Each flag corresponds to a bitmask defined by the Android/Java class file format.
    ///
    /// See: <https://source.android.com/docs/core/runtime/dex-format#access-flags>
    #[derive(Debug)]
    pub struct AccessFlags: u32 {
        /// `ACC_PUBLIC (0x0001)`: Visible everywhere for classes, fields, and methods.
        const PUBLIC = 0x0001;

        /// `ACC_PRIVATE (0x0002)`: Visible only to the defining class.
        const PRIVATE = 0x0002;

        /// `ACC_PROTECTED (0x0004)`: Visible to the package and subclasses.
        const PROTECTED = 0x0004;

        /// `ACC_STATIC (0x0008)`: Static modifier.
        /// * For classes: not constructed with an outer `this`.
        /// * For fields: global to the defining class.
        /// * For methods: does not take a `this` argument.
        const STATIC = 0x0008;

        /// `ACC_FINAL (0x0010)`: Final modifier.
        /// * For classes: not subclassable.
        /// * For fields: immutable after construction.
        /// * For methods: not overridable.
        const FINAL = 0x0010;

        /// `ACC_SYNCHRONIZED (0x0020)`: For methods only.
        /// A lock is automatically acquired around the method call.
        /// Note: May only be set when `ACC_NATIVE` is also set.
        const SYNCHRONIZED = 0x0020;

        /// `ACC_VOLATILE (0x0040)`: For fields only.
        /// Field uses special access rules for thread safety.
        const VOLATILE = 0x0040;

        /// `ACC_BRIDGE (0x0040)`: For methods only.
        /// Marks a bridge method generated by the compiler.
        const BRIDGE = 0x0040;

        /// `ACC_TRANSIENT (0x0080)`: For fields only.
        /// Field is not saved by default serialization.
        const TRANSIENT = 0x0080;

        /// `ACC_VARARGS (0x0080)`: For methods only.
        /// Last argument is a varargs (rest argument).
        const VARARGS = 0x0080;

        /// `ACC_NATIVE (0x0100)`: For methods only.
        /// Method is implemented in native code.
        const NATIVE = 0x0100;

        /// `ACC_INTERFACE (0x0200)`: Class is an interface.
        const INTERFACE = 0x0200;

        /// `ACC_ABSTRACT (0x0400)`:
        /// * For classes: not directly instantiable.
        /// * For methods: unimplemented.
        const ABSTRACT = 0x0400;

        /// `ACC_STRICT (0x0800)`: For methods only.
        /// Enforces strict floating-point rules (`strictfp`).
        const STRICT = 0x0800;

        /// `ACC_SYNTHETIC (0x1000)`: Not directly defined in source code (compiler generated).
        const SYNTHETIC = 0x1000;

        /// `ACC_ANNOTATION (0x2000)`: Declares an annotation class.
        const ANNOTATION = 0x2000;

        /// `ACC_ENUM (0x4000)`: Enum type or enum field.
        const ENUM = 0x4000;

        /// Unused in current specification.
        const UNUSED = 0x8000;

        /// `ACC_CONSTRUCTOR (0x10000)`: Marks a constructor or initializer method.
        const CONSTRUCTOR = 0x10000;

        /// `ACC_DECLARED_SYNCHRONIZED (0x20000)`: Indicates explicitly declared synchronized.
        const DECLARED_SYNCHRONIZED = 0x20000;
    }
}

impl AccessFlags {
    /// Returns `true` if the flag set indicates this is a public member.
    #[inline]
    pub fn is_public(self) -> bool {
        self.contains(Self::PUBLIC)
    }

    /// Returns `true` if the flag set indicates a private member.
    #[inline]
    pub fn is_private(self) -> bool {
        self.contains(Self::PRIVATE)
    }

    /// Returns `true` if the flag set indicates a protected member.
    #[inline]
    pub fn is_protected(self) -> bool {
        self.contains(Self::PROTECTED)
    }

    /// Returns `true` if the flag set includes the static modifier.
    #[inline]
    pub fn is_static(self) -> bool {
        self.contains(Self::STATIC)
    }

    /// Returns `true` if the flag set marks this as final.
    #[inline]
    pub fn is_final(self) -> bool {
        self.contains(Self::FINAL)
    }

    /// Returns `true` if the flag set indicates a synchronized method.
    #[inline]
    pub fn is_synchronized(self) -> bool {
        self.contains(Self::SYNCHRONIZED)
    }

    /// Returns `true` if the flag set marks a volatile field.
    #[inline]
    pub fn is_volatile(self) -> bool {
        self.contains(Self::VOLATILE)
    }

    /// Returns `true` if the flag set marks a bridge method.
    #[inline]
    pub fn is_bridge(self) -> bool {
        self.contains(Self::BRIDGE)
    }

    /// Returns `true` if the flag set marks a transient field.
    #[inline]
    pub fn is_transient(self) -> bool {
        self.contains(Self::TRANSIENT)
    }

    /// Returns `true` if the flag set marks a varargs method.
    #[inline]
    pub fn is_varargs(self) -> bool {
        self.contains(Self::VARARGS)
    }

    /// Returns `true` if this is a native method.
    #[inline]
    pub fn is_native(self) -> bool {
        self.contains(Self::NATIVE)
    }

    /// Returns `true` if this class is an interface.
    #[inline]
    pub fn is_interface(self) -> bool {
        self.contains(Self::INTERFACE)
    }

    /// Returns `true` if this member is abstract.
    #[inline]
    pub fn is_abstract(self) -> bool {
        self.contains(Self::ABSTRACT)
    }

    /// Returns `true` if this method uses strict floating-point rules.
    #[inline]
    pub fn is_strict(self) -> bool {
        self.contains(Self::STRICT)
    }

    /// Returns `true` if the member is synthetic.
    #[inline]
    pub fn is_synthetic(self) -> bool {
        self.contains(Self::SYNTHETIC)
    }

    /// Returns `true` if the type is an annotation class.
    #[inline]
    pub fn is_annotation(self) -> bool {
        self.contains(Self::ANNOTATION)
    }

    /// Returns `true` if the type or field is an enum.
    #[inline]
    pub fn is_enum(self) -> bool {
        self.contains(Self::ENUM)
    }

    /// Returns `true` if the method is a constructor.
    #[inline]
    pub fn is_constructor(self) -> bool {
        self.contains(Self::CONSTRUCTOR)
    }

    /// Returns `true` if the method is declared synchronized.
    #[inline]
    pub fn is_declared_synchronized(self) -> bool {
        self.contains(Self::DECLARED_SYNCHRONIZED)
    }
}

/// Abstraction over `MapItem`
///
/// See: <https://source.android.com/docs/core/runtime/dex-format#map-item>
#[derive(Debug)]
pub struct MapItem {
    /// Type of the items
    pub type_: ItemType,

    /// Unused field
    pub unused: u16,

    /// Count of the number of items to be found at the indicated offset
    pub size: u32,

    /// Offset from the start of the file to the items in question
    pub offset: u32,
}

impl MapItem {
    fn parse(input: &mut &[u8]) -> ModalResult<MapItem> {
        (le_u16.try_map(ItemType::try_from), le_u16, le_u32, le_u32)
            .map(|(type_, unused, size, offset)| MapItem {
                type_,
                unused,
                size,
                offset,
            })
            .parse_next(input)
    }
}

/// DEX item types
///
/// See: <https://source.android.com/docs/core/runtime/dex-format#type-codes>
#[repr(u16)]
#[derive(Debug, PartialEq, Eq)]
pub enum ItemType {
    /// `TYPE_HEADER_ITEM (0x0000)`: Size = 0x70 bytes
    HeaderItem = 0x0000,

    /// `TYPE_STRING_ID_ITEM (0x0001)`: Size = 0x04 bytes
    StringIdItem = 0x0001,

    /// `TYPE_TYPE_ID_ITEM (0x0002)`: Size = 0x04 bytes
    TypeIdItem = 0x0002,

    /// `TYPE_PROTO_ID_ITEM (0x0003)`: Size = 0x0c bytes
    ProtoIdItem = 0x0003,

    /// `TYPE_FIELD_ID_ITEM (0x0004)`: Size = 0x08 bytes
    FieldIdItem = 0x0004,

    /// `TYPE_METHOD_ID_ITEM (0x0005)`: Size = 0x08 bytes
    MethodIdItem = 0x0005,

    /// `TYPE_CLASS_DEF_ITEM (0x0006)`: Size = 0x20 bytes
    ClassDefItem = 0x0006,

    /// `TYPE_CALL_SITE_ID_ITEM (0x0007)`: Size = 0x04 bytes
    CallSiteIdItem = 0x0007,

    /// `TYPE_METHOD_HANDLE_ITEM (0x0008)`: Size = 0x08 bytes
    MethodHandleItem = 0x0008,

    /// `TYPE_MAP_LIST (0x1000)`: Size = 4 + (item.size * 12)
    MapList = 0x1000,

    /// `TYPE_TYPE_LIST (0x1001)`: Size = 4 + (item.size * 2)
    TypeList = 0x1001,

    /// `TYPE_ANNOTATION_SET_REF_LIST (0x1002)`:
    /// Size = 4 + (item.size * 4)
    AnnotationSetRefList = 0x1002,

    /// `TYPE_ANNOTATION_SET_ITEM (0x1003)`:
    /// Size = 4 + (item.size * 4)
    AnnotationSetItem = 0x1003,

    /// `TYPE_CLASS_DATA_ITEM (0x2000)`: Implicit size; must parse
    ClassDataItem = 0x2000,

    /// `TYPE_CODE_ITEM (0x2001)`: Implicit size; must parse
    CodeItem = 0x2001,

    /// `TYPE_STRING_DATA_ITEM (0x2002)`: Implicit size; must parse
    StringDataItem = 0x2002,

    /// `TYPE_DEBUG_INFO_ITEM (0x2003)`: Implicit size; must parse
    DebugInfoItem = 0x2003,

    /// `TYPE_ANNOTATION_ITEM (0x2004)`: Implicit size; must parse
    AnnotationItem = 0x2004,

    /// `TYPE_ENCODED_ARRAY_ITEM (0x2005)`: Implicit size; must parse
    EncodedArrayItem = 0x2005,

    /// `TYPE_ANNOTATIONS_DIRECTORY_ITEM (0x2006)`: Implicit size; must parse
    AnnotationsDirectoryItem = 0x2006,

    /// `TYPE_HIDDENAPI_CLASS_DATA_ITEM (0xF000)`: Implicit size; must parse
    HiddenApiClassDataItem = 0xF000,
}

impl TryFrom<u16> for ItemType {
    type Error = DexError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0000 => Ok(Self::HeaderItem),
            0x0001 => Ok(Self::StringIdItem),
            0x0002 => Ok(Self::TypeIdItem),
            0x0003 => Ok(Self::ProtoIdItem),
            0x0004 => Ok(Self::FieldIdItem),
            0x0005 => Ok(Self::MethodIdItem),
            0x0006 => Ok(Self::ClassDefItem),
            0x0007 => Ok(Self::CallSiteIdItem),
            0x0008 => Ok(Self::MethodHandleItem),
            0x1000 => Ok(Self::MapList),
            0x1001 => Ok(Self::TypeList),
            0x1002 => Ok(Self::AnnotationSetRefList),
            0x1003 => Ok(Self::AnnotationSetItem),
            0x2000 => Ok(Self::ClassDataItem),
            0x2001 => Ok(Self::CodeItem),
            0x2002 => Ok(Self::StringDataItem),
            0x2003 => Ok(Self::DebugInfoItem),
            0x2004 => Ok(Self::AnnotationItem),
            0x2005 => Ok(Self::EncodedArrayItem),
            0x2006 => Ok(Self::AnnotationsDirectoryItem),
            0xF000 => Ok(Self::HiddenApiClassDataItem),
            other => Err(DexError::UnknownTypeItem(other)),
        }
    }
}
