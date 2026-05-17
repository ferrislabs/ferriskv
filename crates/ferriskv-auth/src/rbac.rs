use std::sync::Arc;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Permission {
    Read = 1 << 0,
    Write = 1 << 1,
    Delete = 1 << 2,
    Admin = 1 << 3,
    Watch = 1 << 4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub name: Arc<str>,
    pub permissions: u8,
}

impl Role {
    pub fn new(name: impl Into<Arc<str>>, perms: &[Permission]) -> Self {
        let mut bits = 0u8;
        for p in perms {
            bits |= *p as u8;
        }
        Self {
            name: name.into(),
            permissions: bits,
        }
    }

    #[inline]
    pub fn allows(&self, p: Permission) -> bool {
        (self.permissions & p as u8) != 0
    }
}

#[derive(Debug, Default, Clone)]
pub struct RoleSet {
    roles: Vec<Role>,
}

impl RoleSet {
    pub fn new(roles: Vec<Role>) -> Self {
        Self { roles }
    }

    #[inline]
    pub fn allows(&self, p: Permission) -> bool {
        self.roles.iter().any(|r| r.allows(p))
    }

    pub fn add(&mut self, role: Role) {
        self.roles.push(role);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_bitmask_combines_permissions() {
        let r = Role::new("rw", &[Permission::Read, Permission::Write]);
        assert!(r.allows(Permission::Read));
        assert!(r.allows(Permission::Write));
        assert!(!r.allows(Permission::Delete));
        assert!(!r.allows(Permission::Admin));
    }

    #[test]
    fn role_set_allows_union() {
        let mut set = RoleSet::default();
        set.add(Role::new("read", &[Permission::Read]));
        set.add(Role::new("admin", &[Permission::Admin]));
        assert!(set.allows(Permission::Read));
        assert!(set.allows(Permission::Admin));
        assert!(!set.allows(Permission::Watch));
    }

    #[test]
    fn empty_role_set_denies_everything() {
        let set = RoleSet::default();
        assert!(!set.allows(Permission::Read));
        assert!(!set.allows(Permission::Admin));
    }
}
