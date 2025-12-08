//! Realm 兼容性方法
//!
//! 提供与原有三个 Realm 表兼容的API，用于平滑迁移

use ecies::SecretKey;

use super::error::TenantError;
use super::model::Realm;

/// 兼容性方法 - 用于替换原有的三个表的功能
impl Realm {
    /// 替换 TenantForAuthority::get_all_keys()
    pub async fn get_all_authority_keys() -> Result<Vec<Realm>, TenantError> {
        Self::get_all().await
    }

    /// 替换 TenantForAuthority::get_keys()
    pub async fn get_authority_keys(
        key_id: String,
        realm_id: u32,
    ) -> Result<(Vec<u8>, Vec<u8>), TenantError> {
        let tenant = Self::get_by_tenant_key_id_service(realm_id, &key_id).await?;

        if let Some(t) = tenant {
            let public_key = t.public_key;
            let secret_key = t.secret_key;
            Ok((public_key, secret_key))
        } else {
            Err(TenantError::NotFound)
        }
    }

    /// 替换 TenantForSignaling::get_by_realm_id_and_key_id()
    pub async fn get_signaling_by_realm_id_and_key_id(
        realm_id: u32,
        key_id: &str,
    ) -> Result<SecretKey, TenantError> {
        let tenant = Self::get_by_tenant_key_id_service(realm_id, key_id)
            .await?
            .ok_or(TenantError::NotFound)?;
        SecretKey::parse_slice(tenant.secret_key.as_slice())
            .map_err(|e| TenantError::ParseError(e.to_string()))
    }

    /// 替换 TenantForTurn::get_private_key()
    pub async fn get_private_key(realm_id: u32, key_id: String) -> Result<SecretKey, TenantError> {
        let tenant_opt = Self::get_by_tenant_key_id_service(realm_id, &key_id).await?;

        if let Some(t) = tenant_opt {
            if t.is_expired() {
                return Err(TenantError::KeyExpired);
            }

            SecretKey::parse_slice(t.secret_key.as_slice())
                .map_err(|e| TenantError::ParseError(e.to_string()))
        } else {
            Err(TenantError::KeyNotExist)
        }
    }

    /// 替换 TenantForTurn::get_all_tenants()
    pub async fn get_all_turn_tenants() -> Result<Vec<Realm>, TenantError> {
        Self::get_all().await
    }
}
