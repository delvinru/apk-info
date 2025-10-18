use std::collections::HashSet;

use serde::Serialize;

#[derive(Serialize, Debug)]
pub struct ApkJson {
    pub package_name: Option<String>,

    pub min_sdk_version: Option<String>,

    pub target_sdk_version: Option<String>,

    pub max_sdk_version: Option<String>,

    #[serde(serialize_with = "sorted_set")]
    pub declared_permissions: HashSet<String>,

    pub shared_user_id: Option<String>,

    pub shared_user_label: Option<String>,

    pub shared_user_max_sdk_version: Option<String>,

    pub version_code: Option<String>,

    pub version_name: Option<String>,

    pub install_location: Option<String>,

    #[serde(serialize_with = "sorted_set")]
    pub features: HashSet<String>,

    #[serde(serialize_with = "sorted_set")]
    pub permissions: HashSet<String>,

    #[serde(serialize_with = "sorted_set")]
    pub permissions_sdk23: HashSet<String>,
}

fn sorted_set<S>(set: &HashSet<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut vec: Vec<_> = set.iter().collect();
    vec.sort();
    vec.serialize(serializer)
}
