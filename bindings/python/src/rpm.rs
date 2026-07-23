//! Python adapter for the concrete unpack-only RPM reader.

use std::{io, path::PathBuf, sync::Arc};

use pyo3::{
    exceptions::PyMemoryError,
    prelude::*,
    types::{PyBytes, PyDict, PyList},
};
use unpackio::{
    Error, Result as CoreResult, RpmArchive as CoreRpmArchive, RpmEntry as CoreRpmEntry,
    RpmEntrySink, RpmHeader as CoreRpmHeader, RpmPayloadCompression, RpmValue, UnsafePathReason,
    validate_safe_path,
};

use crate::{
    archive::copy_input_for,
    callback::{PythonSink, SinkMode, callback_continues},
    config::{PyCancellationToken, PyLimits, cancellation_or_new, limits_or_default, work_budget},
    errors::{PythonCallbackError, detached_core_for, guard},
};

fn compression_name(compression: RpmPayloadCompression) -> &'static str {
    match compression {
        RpmPayloadCompression::None => "none",
        RpmPayloadCompression::Gzip => "gzip",
        RpmPayloadCompression::Bzip2 => "bzip2",
        RpmPayloadCompression::Xz => "xz",
        RpmPayloadCompression::Lzma => "lzma",
        RpmPayloadCompression::Zstandard => "zstandard",
        RpmPayloadCompression::Unknown => "unknown",
        _ => "unknown",
    }
}

fn unsafe_path_reason_name(reason: UnsafePathReason) -> &'static str {
    match reason {
        UnsafePathReason::Empty => "empty",
        UnsafePathReason::Nul => "nul",
        UnsafePathReason::Absolute => "absolute",
        UnsafePathReason::Unc => "unc",
        UnsafePathReason::Drive => "drive",
        UnsafePathReason::Traversal => "traversal",
        _ => "unknown",
    }
}

fn entry_kind(mode: u32) -> &'static str {
    match mode & 0o170_000 {
        0o040_000 => "directory",
        0o100_000 => "file",
        0o120_000 => "symlink",
        0o010_000 => "fifo",
        0o020_000 => "character_device",
        0o060_000 => "block_device",
        0o140_000 => "socket",
        _ => "unknown",
    }
}

/// One owned Python snapshot of an RPM CPIO member.
#[pyclass(
    name = "RpmEntry",
    module = "unpackio._native",
    frozen,
    skip_from_py_object
)]
#[derive(Clone)]
pub(crate) struct PyRpmEntry {
    #[pyo3(get)]
    index: u64,
    raw_name: Vec<u8>,
    #[pyo3(get)]
    name: String,
    #[pyo3(get)]
    kind: String,
    #[pyo3(get)]
    inode: u32,
    #[pyo3(get)]
    mode: u32,
    #[pyo3(get)]
    permissions: u32,
    #[pyo3(get)]
    uid: u32,
    #[pyo3(get)]
    gid: u32,
    #[pyo3(get)]
    link_count: u32,
    #[pyo3(get)]
    modified_time: u64,
    #[pyo3(get)]
    size: u64,
    #[pyo3(get)]
    device_major: u32,
    #[pyo3(get)]
    device_minor: u32,
    #[pyo3(get)]
    rdev_major: u32,
    #[pyo3(get)]
    rdev_minor: u32,
    #[pyo3(get)]
    checksum: Option<u32>,
    #[pyo3(get)]
    is_directory: bool,
    #[pyo3(get)]
    is_symlink: bool,
    #[pyo3(get)]
    is_safe_path: bool,
    #[pyo3(get)]
    unsafe_path_reason: Option<String>,
}

impl PyRpmEntry {
    pub(crate) fn from_core(entry: &CoreRpmEntry) -> Self {
        let name = entry.name_lossy();
        let (is_safe_path, unsafe_path_reason) = match validate_safe_path(&name) {
            Ok(()) => (true, None),
            Err(reason) => (false, Some(unsafe_path_reason_name(reason).to_owned())),
        };
        Self {
            index: entry.index(),
            raw_name: entry.raw_name().to_vec(),
            name,
            kind: entry_kind(entry.mode()).to_owned(),
            inode: entry.inode(),
            mode: entry.mode(),
            permissions: entry.mode() & 0o7777,
            uid: entry.uid(),
            gid: entry.gid(),
            link_count: entry.link_count(),
            modified_time: entry.modified_time(),
            size: entry.size(),
            device_major: entry.device_major(),
            device_minor: entry.device_minor(),
            rdev_major: entry.rdev_major(),
            rdev_minor: entry.rdev_minor(),
            checksum: entry.checksum(),
            is_directory: entry.is_directory(),
            is_symlink: entry.is_symlink(),
            is_safe_path,
            unsafe_path_reason,
        }
    }
}

#[pymethods]
impl PyRpmEntry {
    #[getter]
    fn raw_name(&self, py: Python<'_>) -> Py<PyBytes> {
        PyBytes::new(py, &self.raw_name).unbind()
    }

    fn __repr__(&self) -> String {
        format!(
            "RpmEntry(index={}, name={:?}, kind={:?}, size={})",
            self.index, self.name, self.kind, self.size
        )
    }
}

fn value_type_name(value: &RpmValue) -> &'static str {
    match value {
        RpmValue::Null => "null",
        RpmValue::Char(_) => "char",
        RpmValue::Int8(_) => "int8",
        RpmValue::Int16(_) => "int16",
        RpmValue::Int32(_) => "int32",
        RpmValue::Int64(_) => "int64",
        RpmValue::String(_) => "string",
        RpmValue::Binary(_) => "binary",
        RpmValue::StringArray(_) => "string_array",
        RpmValue::I18nString(_) => "i18n_string",
        _ => "unknown",
    }
}

fn value_to_python(py: Python<'_>, value: &RpmValue) -> PyResult<Py<PyAny>> {
    match value {
        RpmValue::Null => Ok(py.None()),
        RpmValue::Char(bytes)
        | RpmValue::Int8(bytes)
        | RpmValue::String(bytes)
        | RpmValue::Binary(bytes) => Ok(PyBytes::new(py, bytes).into_any().unbind()),
        RpmValue::Int16(values) => Ok(PyList::new(py, values.iter().copied())?.into_any().unbind()),
        RpmValue::Int32(values) => Ok(PyList::new(py, values.iter().copied())?.into_any().unbind()),
        RpmValue::Int64(values) => Ok(PyList::new(py, values.iter().copied())?.into_any().unbind()),
        RpmValue::StringArray(values) | RpmValue::I18nString(values) => {
            let items = values.iter().map(|value| PyBytes::new(py, value));
            Ok(PyList::new(py, items)?.into_any().unbind())
        }
        _ => Ok(py.None()),
    }
}

fn named_value_to_python(py: Python<'_>, value: &RpmValue) -> PyResult<Py<PyAny>> {
    match value {
        RpmValue::Int16(values) if values.len() == 1 => Ok(values
            .first()
            .copied()
            .ok_or_else(|| PyMemoryError::new_err("RPM INT16 scalar is missing"))?
            .into_pyobject(py)
            .map(|value| value.into_any().unbind())?),
        RpmValue::Int32(values) if values.len() == 1 => Ok(values
            .first()
            .copied()
            .ok_or_else(|| PyMemoryError::new_err("RPM INT32 scalar is missing"))?
            .into_pyobject(py)
            .map(|value| value.into_any().unbind())?),
        RpmValue::Int64(values) if values.len() == 1 => Ok(values
            .first()
            .copied()
            .ok_or_else(|| PyMemoryError::new_err("RPM INT64 scalar is missing"))?
            .into_pyobject(py)
            .map(|value| value.into_any().unbind())?),
        RpmValue::I18nString(values) => match values.first() {
            Some(value) => Ok(PyBytes::new(py, value).into_any().unbind()),
            None => Ok(PyBytes::new(py, &[]).into_any().unbind()),
        },
        _ => value_to_python(py, value),
    }
}

// This is the complete public tag-name projection used by the Python API.
// Canonical spellings replace two duplicate typo aliases. Unknown identifiers
// deliberately remain numeric instead of being discarded. Exact source
// provenance is recorded in PROVENANCE.md.
fn main_tag_name(tag: u32) -> Option<&'static str> {
    match tag {
        61 => Some("headerimage"),
        62 => Some("headersignatures"),
        63 => Some("headerimmutable"),
        64 => Some("headerregions"),
        100 => Some("headeri18ntable"),
        256 => Some("sig_base"),
        257 => Some("sigsize"),
        258 => Some("siglemd5_1"),
        259 => Some("sigpgp"),
        260 => Some("siglemd5_2"),
        261 => Some("sigmd5"),
        262 => Some("siggpg"),
        263 => Some("sigpgp5"),
        264 => Some("badsha1_1"),
        265 => Some("badsha1_2"),
        266 => Some("pubkeys"),
        267 => Some("signature"),
        268 => Some("rsaheader"),
        269 => Some("md5"),
        270 => Some("longsigsize"),
        271 => Some("longarchivesize"),
        273 => Some("sha256"),
        276 => Some("veritysignatures"),
        277 => Some("veritysignaturealgo"),
        1000 => Some("name"),
        1001 => Some("version"),
        1002 => Some("release"),
        1003 => Some("serial"),
        1004 => Some("summary"),
        1005 => Some("description"),
        1006 => Some("buildtime"),
        1007 => Some("buildhost"),
        1008 => Some("installtime"),
        1009 => Some("size"),
        1010 => Some("distribution"),
        1011 => Some("vendor"),
        1012 => Some("gif"),
        1013 => Some("xpm"),
        1014 => Some("copyright"),
        1015 => Some("packager"),
        1016 => Some("group"),
        1017 => Some("changelog"),
        1018 => Some("source"),
        1019 => Some("patch"),
        1020 => Some("url"),
        1021 => Some("os"),
        1022 => Some("arch"),
        1023 => Some("prein"),
        1024 => Some("postin"),
        1025 => Some("preun"),
        1026 => Some("postun"),
        1027 => Some("oldfilenames"),
        1028 => Some("filesizes"),
        1029 => Some("filestates"),
        1030 => Some("filemodes"),
        1031 => Some("fileuids"),
        1032 => Some("filegids"),
        1033 => Some("filerdevs"),
        1034 => Some("filemtimes"),
        1035 => Some("filemd5s"),
        1036 => Some("filelinktos"),
        1037 => Some("fileflags"),
        1038 => Some("root"),
        1039 => Some("fileusername"),
        1040 => Some("filegroupname"),
        1041 => Some("exclude"),
        1042 => Some("exclusive"),
        1043 => Some("icon"),
        1044 => Some("sourcerpm"),
        1045 => Some("fileverifyflags"),
        1046 => Some("archivesize"),
        1047 => Some("provides"),
        1048 => Some("requireflags"),
        1049 => Some("requirename"),
        1050 => Some("requireversion"),
        1051 => Some("nosource"),
        1052 => Some("nopatch"),
        1053 => Some("conflictflags"),
        1054 => Some("conflictname"),
        1055 => Some("conflictversion"),
        1056 => Some("defaultprefix"),
        1057 => Some("buildroot"),
        1058 => Some("installprefix"),
        1059 => Some("excludearch"),
        1060 => Some("excludeos"),
        1061 => Some("exclusivearch"),
        1062 => Some("exclusiveos"),
        1063 => Some("autoreqprov"),
        1064 => Some("rpmversion"),
        1065 => Some("triggerscripts"),
        1066 => Some("triggername"),
        1067 => Some("triggerversion"),
        1068 => Some("triggerflags"),
        1069 => Some("triggerindex"),
        1079 => Some("verifyscript"),
        1080 => Some("changelogtime"),
        1081 => Some("authors"),
        1082 => Some("comments"),
        1084 => Some("prereq"),
        1085 => Some("preinprog"),
        1086 => Some("postinprog"),
        1087 => Some("preunprog"),
        1088 => Some("postunprog"),
        1089 => Some("buildarchs"),
        1090 => Some("obsoletes"),
        1091 => Some("verifyscriptprog"),
        1092 => Some("triggerscriptprog"),
        1093 => Some("docdir"),
        1094 => Some("cookie"),
        1095 => Some("filedevices"),
        1096 => Some("fileinodes"),
        1097 => Some("filelangs"),
        1098 => Some("prefixes"),
        1099 => Some("instprefixes"),
        1100 => Some("triggerin"),
        1101 => Some("triggerun"),
        1102 => Some("triggerpostun"),
        1103 => Some("autoreq"),
        1104 => Some("autoprov"),
        1105 => Some("capability"),
        1106 => Some("sourcepackage"),
        1107 => Some("oldorigfilenames"),
        1108 => Some("buildprereq"),
        1109 => Some("buildrequires"),
        1110 => Some("buildconflicts"),
        1111 => Some("buildmacros"),
        1112 => Some("provideflags"),
        1113 => Some("provideversion"),
        1114 => Some("obsoleteflags"),
        1115 => Some("obsoleteversion"),
        1116 => Some("dirindexes"),
        1117 => Some("basenames"),
        1118 => Some("dirnames"),
        1119 => Some("origdirindexes"),
        1120 => Some("origbasenames"),
        1121 => Some("origdirnames"),
        1122 => Some("optflags"),
        1123 => Some("disturl"),
        1124 => Some("archive_format"),
        1125 => Some("archive_compression"),
        1126 => Some("payloadflags"),
        1127 => Some("installcolor"),
        1128 => Some("installtid"),
        1129 => Some("removetid"),
        1131 => Some("rhnplatform"),
        1132 => Some("target"),
        1133 => Some("patchesname"),
        1134 => Some("patchesflags"),
        1135 => Some("patchesversion"),
        1136 => Some("cachectime"),
        1137 => Some("cachepkgpath"),
        1138 => Some("cachepkgsize"),
        1139 => Some("cachepkgmtime"),
        1140 => Some("filecolors"),
        1141 => Some("fileclass"),
        1142 => Some("classdict"),
        1143 => Some("filedependsx"),
        1144 => Some("filedependsn"),
        1145 => Some("dependsdict"),
        1146 => Some("sourcepkgid"),
        1147 => Some("filecontexts"),
        1148 => Some("fscontexts"),
        1149 => Some("recontexts"),
        1150 => Some("policies"),
        1151 => Some("pretrans"),
        1152 => Some("posttrans"),
        1153 => Some("pretransprog"),
        1154 => Some("posttransprog"),
        1155 => Some("disttag"),
        1156 => Some("oldsuggestsname"),
        1157 => Some("oldsuggestsversion"),
        1158 => Some("oldsuggestsflags"),
        1159 => Some("oldenhancesname"),
        1160 => Some("oldenhancesversion"),
        1161 => Some("oldenhancesflags"),
        1162 => Some("priority"),
        1163 => Some("cvsid"),
        1164 => Some("blinkpkgid"),
        1165 => Some("blinkhdrid"),
        1166 => Some("blinknevra"),
        1167 => Some("flinkpkgid"),
        1168 => Some("flinkhdrid"),
        1169 => Some("flinknevra"),
        1170 => Some("packageorigin"),
        1171 => Some("triggerprein"),
        1172 => Some("buildsuggests"),
        1173 => Some("buildenhances"),
        1174 => Some("scriptstates"),
        1175 => Some("scriptmetrics"),
        1176 => Some("buildcpuclock"),
        1177 => Some("filedigestalgos"),
        1178 => Some("variants"),
        1179 => Some("xmajor"),
        1180 => Some("xminor"),
        1181 => Some("repotag"),
        1182 => Some("keywords"),
        1183 => Some("buildplatforms"),
        1184 => Some("packagecolor"),
        1185 => Some("packageprefcolor"),
        1186 => Some("xattrsdict"),
        1187 => Some("filexattrsx"),
        1188 => Some("depattrsdict"),
        1189 => Some("conflictattrsx"),
        1190 => Some("obsoleteattrsx"),
        1191 => Some("provideattrsx"),
        1192 => Some("requireattrsx"),
        1193 => Some("buildprovides"),
        1194 => Some("buildobsoletes"),
        1195 => Some("dbinstance"),
        1196 => Some("nvra"),
        5000 => Some("filenames"),
        5001 => Some("fileprovide"),
        5002 => Some("filerequire"),
        5003 => Some("fsnames"),
        5004 => Some("fssizes"),
        5005 => Some("triggerconds"),
        5006 => Some("triggertype"),
        5007 => Some("origfilenames"),
        5008 => Some("longfilesizes"),
        5009 => Some("longsize"),
        5010 => Some("filecaps"),
        5011 => Some("filedigestalgo"),
        5012 => Some("bugurl"),
        5013 => Some("evr"),
        5014 => Some("nvr"),
        5015 => Some("nevr"),
        5016 => Some("nevra"),
        5017 => Some("headercolor"),
        5018 => Some("verbose"),
        5019 => Some("epochnum"),
        5020 => Some("preinflags"),
        5021 => Some("postinflags"),
        5022 => Some("preunflags"),
        5023 => Some("postunflags"),
        5024 => Some("pretransflags"),
        5025 => Some("posttransflags"),
        5026 => Some("verifyscriptflags"),
        5027 => Some("triggerscriptflags"),
        5029 => Some("collections"),
        5030 => Some("policynames"),
        5031 => Some("policytypes"),
        5032 => Some("policytypesindexes"),
        5033 => Some("policyflags"),
        5034 => Some("vcs"),
        5035 => Some("ordername"),
        5036 => Some("orderversion"),
        5037 => Some("orderflags"),
        5038 => Some("mssfmanifest"),
        5039 => Some("mssfdomain"),
        5040 => Some("instfilenames"),
        5041 => Some("requirenevrs"),
        5042 => Some("providenevrs"),
        5043 => Some("obsoletenevrs"),
        5044 => Some("conflictnevrs"),
        5045 => Some("filenlinks"),
        5046 => Some("recommendname"),
        5047 => Some("recommendversion"),
        5048 => Some("recommendflags"),
        5049 => Some("suggestname"),
        5050 => Some("suggestversion"),
        5051 => Some("suggestflags"),
        5052 => Some("supplementname"),
        5053 => Some("supplementversion"),
        5054 => Some("supplementflags"),
        5055 => Some("enhancename"),
        5056 => Some("enhanceversion"),
        5057 => Some("enhanceflags"),
        5058 => Some("recommendnevrs"),
        5059 => Some("suggestnevrs"),
        5060 => Some("supplementnevrs"),
        5061 => Some("enhancenevrs"),
        5062 => Some("encoding"),
        5063 => Some("filetriggerin"),
        5064 => Some("filetriggerun"),
        5065 => Some("filetriggerpostun"),
        5066 => Some("filetriggerscripts"),
        5067 => Some("filetriggerscriptprog"),
        5068 => Some("filetriggerscriptflags"),
        5069 => Some("filetriggername"),
        5070 => Some("filetriggerindex"),
        5071 => Some("filetriggerversion"),
        5072 => Some("filetriggerflags"),
        5073 => Some("transfiletriggerin"),
        5074 => Some("transfiletriggerun"),
        5075 => Some("transfiletriggerpostun"),
        5076 => Some("transfiletriggerscripts"),
        5077 => Some("transfiletriggerscriptprog"),
        5078 => Some("transfiletriggerscriptflags"),
        5079 => Some("transfiletriggername"),
        5080 => Some("transfiletriggerindex"),
        5081 => Some("transfiletriggerversion"),
        5082 => Some("transfiletriggerflags"),
        5083 => Some("removepathpostfixes"),
        5084 => Some("filetriggerpriorities"),
        5085 => Some("transfiletriggerpriorities"),
        5086 => Some("filetriggerconds"),
        5087 => Some("filetriggertype"),
        5088 => Some("transfiletriggerconds"),
        5089 => Some("transfiletriggertype"),
        5090 => Some("filesignatures"),
        5091 => Some("filesignaturelength"),
        5092 => Some("payloaddigest"),
        5093 => Some("payloaddigestalgo"),
        5094 => Some("autoinstalled"),
        5095 => Some("identity"),
        5096 => Some("modularitylabel"),
        5097 => Some("payloaddigestalt"),
        5098 => Some("archsuffix"),
        5099 => Some("spec"),
        5100 => Some("translationurl"),
        5101 => Some("upstreamreleases"),
        5102 => Some("sourcelicense"),
        5103 => Some("preuntrans"),
        5104 => Some("postuntrans"),
        5105 => Some("preuntransprog"),
        5106 => Some("postuntransprog"),
        5107 => Some("preuntransflags"),
        5108 => Some("postuntransflags"),
        5109 => Some("sysusers"),
        _ => None,
    }
}

fn signature_tag_name(tag: u32) -> Option<&'static str> {
    match tag {
        61 => Some("headerimage"),
        62 => Some("headersignatures"),
        264 => Some("badsha1_1"),
        265 => Some("badsha1_2"),
        267 => Some("signature"),
        268 => Some("rsaheader"),
        269 => Some("md5"),
        270 => Some("longsigsize"),
        271 => Some("longarchivesize"),
        273 => Some("sha256"),
        274 => Some("filesignatures"),
        275 => Some("filesignaturelength"),
        276 => Some("veritysignatures"),
        277 => Some("veritysignaturealgo"),
        1000 => Some("size"),
        1001 => Some("lemd5_1"),
        1002 => Some("pgp"),
        1003 => Some("lemd5_2"),
        1004 => Some("sigmd5"),
        1005 => Some("gpg"),
        1006 => Some("pgp5"),
        1007 => Some("payloadsize"),
        1008 => Some("reservedspace"),
        _ => None,
    }
}

/// One typed RPM header entry.
#[pyclass(
    name = "RpmHeaderEntry",
    module = "unpackio._native",
    frozen,
    skip_from_py_object
)]
#[derive(Clone)]
pub(crate) struct PyRpmHeaderEntry {
    #[pyo3(get)]
    tag: u32,
    #[pyo3(get)]
    value_type: String,
    value: RpmValue,
}

impl PyRpmHeaderEntry {
    fn from_core(entry: &unpackio::RpmHeaderEntry) -> Self {
        Self {
            tag: entry.tag(),
            value_type: value_type_name(entry.value()).to_owned(),
            value: entry.value().clone(),
        }
    }
}

#[pymethods]
impl PyRpmHeaderEntry {
    #[getter]
    fn value(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        guard(|| value_to_python(py, &self.value))
    }

    fn __repr__(&self) -> String {
        format!(
            "RpmHeaderEntry(tag={}, value_type={:?})",
            self.tag, self.value_type
        )
    }
}

/// An owned snapshot of an RPM signature or main header.
#[pyclass(
    name = "RpmHeader",
    module = "unpackio._native",
    frozen,
    skip_from_py_object
)]
#[derive(Clone)]
pub(crate) struct PyRpmHeader {
    entries: Vec<PyRpmHeaderEntry>,
    #[pyo3(get)]
    raw_size: u64,
}

impl PyRpmHeader {
    fn from_core(header: &CoreRpmHeader) -> PyResult<Self> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(header.entries().len())
            .map_err(|_| PyMemoryError::new_err("unable to allocate RPM header metadata"))?;
        entries.extend(header.entries().iter().map(PyRpmHeaderEntry::from_core));
        Ok(Self {
            entries,
            raw_size: header.raw_size(),
        })
    }
}

#[pymethods]
impl PyRpmHeader {
    fn __len__(&self) -> usize {
        self.entries.len()
    }

    fn entries(&self) -> Vec<PyRpmHeaderEntry> {
        self.entries.clone()
    }

    fn value(&self, py: Python<'_>, tag: u32) -> PyResult<Option<Py<PyAny>>> {
        guard(|| {
            self.entries
                .iter()
                .rev()
                .find(|entry| entry.tag == tag)
                .map(|entry| value_to_python(py, &entry.value))
                .transpose()
        })
    }

    fn as_dict(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        guard(|| {
            let dictionary = PyDict::new(py);
            for entry in &self.entries {
                dictionary.set_item(entry.tag, value_to_python(py, &entry.value)?)?;
            }
            Ok(dictionary.unbind())
        })
    }

    /// Projects symbolic tags and scalar values for application-facing metadata.
    #[pyo3(signature = (*, signature=false))]
    fn as_named_dict(&self, py: Python<'_>, signature: bool) -> PyResult<Py<PyDict>> {
        guard(|| {
            let dictionary = PyDict::new(py);
            for entry in &self.entries {
                let value = named_value_to_python(py, &entry.value)?;
                let name = if signature {
                    signature_tag_name(entry.tag)
                } else {
                    main_tag_name(entry.tag)
                };
                match name {
                    Some(name) => dictionary.set_item(name, value)?,
                    None => dictionary.set_item(entry.tag, value)?,
                }
            }
            Ok(dictionary.unbind())
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "RpmHeader(entries={}, raw_size={})",
            self.entries.len(),
            self.raw_size
        )
    }
}

/// Opens RPM bytes without auto-detecting or creating filesystem paths.
#[pyfunction]
#[pyo3(signature = (data, *, limits=None, cancellation=None,
    max_work_units=1_000_000_000))]
pub(crate) fn open_rpm_bytes(
    py: Python<'_>,
    data: &Bound<'_, PyBytes>,
    limits: Option<PyRef<'_, PyLimits>>,
    cancellation: Option<PyRef<'_, PyCancellationToken>>,
    max_work_units: u64,
) -> PyResult<PyRpmArchive> {
    guard(|| {
        let limits = limits_or_default(limits.as_deref());
        let cancellation = cancellation_or_new(cancellation.as_deref());
        let bytes = copy_input_for(py, data, limits, "rpm")?;
        detached_core_for(py, "rpm", move || {
            let mut budget = work_budget(max_work_units);
            CoreRpmArchive::open_bytes(bytes, limits, &cancellation, &mut budget)
        })
        .map(PyRpmArchive::new)
    })
}

/// Opens an RPM path without choosing any extraction destination.
#[pyfunction]
#[pyo3(signature = (path, *, limits=None, cancellation=None,
    max_work_units=1_000_000_000))]
pub(crate) fn open_rpm_path(
    py: Python<'_>,
    path: PathBuf,
    limits: Option<PyRef<'_, PyLimits>>,
    cancellation: Option<PyRef<'_, PyCancellationToken>>,
    max_work_units: u64,
) -> PyResult<PyRpmArchive> {
    guard(|| {
        let limits = limits_or_default(limits.as_deref());
        let cancellation = cancellation_or_new(cancellation.as_deref());
        detached_core_for(py, "rpm", move || {
            let mut budget = work_budget(max_work_units);
            CoreRpmArchive::open_path(&path, limits, &cancellation, &mut budget)
        })
        .map(PyRpmArchive::new)
    })
}

/// An owned RPM session with caller-directed CPIO extraction only.
#[pyclass(name = "RpmArchive", module = "unpackio._native", frozen)]
pub(crate) struct PyRpmArchive {
    value: Arc<CoreRpmArchive>,
}

impl PyRpmArchive {
    fn new(value: CoreRpmArchive) -> Self {
        Self {
            value: Arc::new(value),
        }
    }

    fn metadata(&self) -> PyResult<Vec<PyRpmEntry>> {
        let entries = self.value.entries();
        let mut output = Vec::new();
        output
            .try_reserve_exact(entries.len())
            .map_err(|_| PyMemoryError::new_err("unable to allocate RPM metadata list"))?;
        output.extend(entries.iter().map(PyRpmEntry::from_core));
        Ok(output)
    }
}

#[pymethods]
impl PyRpmArchive {
    fn __len__(&self) -> PyResult<usize> {
        guard(|| Ok(self.value.entries().len()))
    }

    fn __repr__(&self) -> PyResult<String> {
        guard(|| {
            Ok(format!(
                "RpmArchive(entries={}, compression={:?}, retained_payload_bytes={})",
                self.value.entries().len(),
                compression_name(self.value.payload_compression()),
                self.value.retained_payload_bytes()
            ))
        })
    }

    fn entries(&self) -> PyResult<Vec<PyRpmEntry>> {
        guard(|| self.metadata())
    }

    fn entry(&self, index: u64) -> PyResult<Option<PyRpmEntry>> {
        guard(|| Ok(self.value.entry(index).map(PyRpmEntry::from_core)))
    }

    #[getter]
    fn payload_compression(&self) -> PyResult<String> {
        guard(|| Ok(compression_name(self.value.payload_compression()).to_owned()))
    }

    #[getter]
    fn limits(&self) -> PyResult<PyLimits> {
        guard(|| Ok(PyLimits::from_core(self.value.limits())))
    }

    #[getter]
    fn retained_payload_bytes(&self) -> PyResult<usize> {
        guard(|| Ok(self.value.retained_payload_bytes()))
    }

    #[getter]
    fn lead_name(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        guard(|| Ok(PyBytes::new(py, self.value.lead().name()).unbind()))
    }

    #[getter]
    fn lead_version(&self) -> PyResult<(u8, u8)> {
        guard(|| Ok((self.value.lead().major(), self.value.lead().minor())))
    }

    #[getter]
    fn lead_package_type(&self) -> PyResult<u16> {
        guard(|| Ok(self.value.lead().package_type()))
    }

    #[getter]
    fn lead_architecture(&self) -> PyResult<u16> {
        guard(|| Ok(self.value.lead().architecture()))
    }

    #[getter]
    fn lead_operating_system(&self) -> PyResult<u16> {
        guard(|| Ok(self.value.lead().operating_system()))
    }

    #[getter]
    fn lead_signature_type(&self) -> PyResult<u16> {
        guard(|| Ok(self.value.lead().signature_type()))
    }

    #[getter]
    fn lead_reserved(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        guard(|| Ok(PyBytes::new(py, self.value.lead().reserved()).unbind()))
    }

    #[getter]
    fn signature_header(&self) -> PyResult<PyRpmHeader> {
        guard(|| PyRpmHeader::from_core(self.value.signature_header()))
    }

    #[getter]
    fn header(&self) -> PyResult<PyRpmHeader> {
        guard(|| PyRpmHeader::from_core(self.value.header()))
    }

    #[pyo3(signature = (*, cancellation=None, max_work_units=1_000_000_000))]
    fn verify(
        &self,
        py: Python<'_>,
        cancellation: Option<PyRef<'_, PyCancellationToken>>,
        max_work_units: u64,
    ) -> PyResult<()> {
        guard(|| {
            let archive = Arc::clone(&self.value);
            let cancellation = cancellation_or_new(cancellation.as_deref());
            detached_core_for(py, "rpm", move || {
                let mut budget = work_budget(max_work_units);
                archive.verify(&cancellation, &mut budget)
            })
        })
    }

    #[pyo3(signature = (index, writer, *, cancellation=None,
        max_work_units=1_000_000_000))]
    fn extract_entry_to(
        &self,
        py: Python<'_>,
        index: u64,
        writer: Py<PyAny>,
        cancellation: Option<PyRef<'_, PyCancellationToken>>,
        max_work_units: u64,
    ) -> PyResult<u64> {
        guard(|| {
            let archive = Arc::clone(&self.value);
            let cancellation = cancellation_or_new(cancellation.as_deref());
            let sink_cancellation = cancellation.clone();
            detached_core_for(py, "rpm", move || {
                let mut budget = work_budget(max_work_units);
                let mut sink = PythonSink::new(writer, SinkMode::Writer, sink_cancellation);
                archive.extract_entry_to(index, &mut sink, &cancellation, &mut budget)
            })
        })
    }

    #[pyo3(signature = (index, callback, *, cancellation=None,
        max_work_units=1_000_000_000))]
    fn stream_entry(
        &self,
        py: Python<'_>,
        index: u64,
        callback: Py<PyAny>,
        cancellation: Option<PyRef<'_, PyCancellationToken>>,
        max_work_units: u64,
    ) -> PyResult<u64> {
        guard(|| {
            let archive = Arc::clone(&self.value);
            let cancellation = cancellation_or_new(cancellation.as_deref());
            let sink_cancellation = cancellation.clone();
            detached_core_for(py, "rpm", move || {
                let mut budget = work_budget(max_work_units);
                let mut sink = PythonSink::new(callback, SinkMode::Callback, sink_cancellation);
                archive.extract_entry_to(index, &mut sink, &cancellation, &mut budget)
            })
        })
    }

    #[pyo3(signature = (sink, *, cancellation=None, max_work_units=1_000_000_000))]
    fn extract_entries_to(
        &self,
        py: Python<'_>,
        sink: Py<PyAny>,
        cancellation: Option<PyRef<'_, PyCancellationToken>>,
        max_work_units: u64,
    ) -> PyResult<u64> {
        guard(|| {
            let archive = Arc::clone(&self.value);
            let cancellation = cancellation_or_new(cancellation.as_deref());
            let sink_cancellation = cancellation.clone();
            detached_core_for(py, "rpm", move || {
                let mut budget = work_budget(max_work_units);
                let mut sink = PythonRpmEntrySink {
                    target: sink,
                    cancellation: sink_cancellation,
                };
                archive.extract_entries_to(&mut sink, &cancellation, &mut budget)
            })
        })
    }
}

struct PythonRpmEntrySink {
    target: Py<PyAny>,
    cancellation: unpackio::CancellationToken,
}

impl PythonRpmEntrySink {
    fn finish_callback(&self, result: PyResult<bool>) -> CoreResult<()> {
        match result {
            Ok(true) => self.cancellation.check(),
            Ok(false) => {
                self.cancellation.cancel();
                Err(Error::Cancelled)
            }
            Err(error) => Err(Error::Io(io::Error::other(PythonCallbackError::new(error)))),
        }
    }
}

impl RpmEntrySink for PythonRpmEntrySink {
    fn begin_entry(&mut self, core_entry: &CoreRpmEntry) -> CoreResult<()> {
        let result = Python::attach(|py| {
            let size = core_entry.size();
            let entry = Py::new(py, PyRpmEntry::from_core(core_entry))?;
            let result = self
                .target
                .bind(py)
                .call_method1("begin_entry", (entry, size))?;
            callback_continues(
                &result,
                "RPM entry sink begin_entry() must return None or bool",
            )
        });
        self.finish_callback(result)
    }

    fn write_entry(&mut self, entry_index: u64, bytes: &[u8]) -> CoreResult<()> {
        let result = Python::attach(|py| {
            let chunk = PyBytes::new_with(py, bytes.len(), |output| {
                output.copy_from_slice(bytes);
                Ok(())
            })?;
            let result = self
                .target
                .bind(py)
                .call_method1("write_entry", (entry_index, chunk))?;
            callback_continues(
                &result,
                "RPM entry sink write_entry() must return None or bool",
            )
        });
        self.finish_callback(result)
    }

    fn finish_entry(&mut self, entry_index: u64) -> CoreResult<()> {
        let result = Python::attach(|py| {
            let result = self
                .target
                .bind(py)
                .call_method1("finish_entry", (entry_index,))?;
            callback_continues(
                &result,
                "RPM entry sink finish_entry() must return None or bool",
            )
        });
        self.finish_callback(result)
    }
}
