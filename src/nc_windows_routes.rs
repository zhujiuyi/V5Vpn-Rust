use std::{io, net::Ipv4Addr, ptr, slice};

use anyhow::{Context, Result, ensure};
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR},
    NetworkManagement::IpHelper::{
        CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable, GetBestRoute2,
        GetIpForwardEntry2, GetIpForwardTable2, GetUnicastIpAddressTable, IP_ADDRESS_PREFIX,
        InitializeIpForwardEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
        MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE, SetIpForwardEntry2,
    },
    Networking::WinSock::{
        AF_INET, IN_ADDR, IN_ADDR_0, IpDadStatePreferred, MIB_IPPROTO_NETMGMT, SOCKADDR_IN,
        SOCKADDR_INET,
    },
};

use crate::nc_policy::Ipv4Cidr;

// This is an ActiveStore route. A finite lifetime also bounds stale routing if
// the client exits without running its cleanup.
const LEASE_SECONDS: u32 = 120;

pub(crate) struct Routes {
    next_hop: Ipv4Addr,
    local_host: Ipv4Addr,
    rows: Vec<MIB_IPFORWARD_ROW2>,
}

impl Routes {
    pub(crate) fn install(
        routes: &[Ipv4Cidr],
        next_hop: Ipv4Addr,
        local_host: Ipv4Addr,
    ) -> Result<Self> {
        ensure!(!routes.is_empty(), "NC 网关没有可安装的授权路由");
        ensure!(
            next_hop != local_host && [next_hop, local_host].into_iter().all(is_unicast),
            "WSL2 网卡的 IPv4 地址无效"
        );
        for cidr in routes {
            ensure!(
                cidr.prefix <= 32 && contains(cidr.network, cidr.prefix, cidr.network),
                "NC 授权 IPv4 前缀无效"
            );
            ensure!(
                !contains(cidr.network, cidr.prefix, local_host)
                    && !contains(cidr.network, cidr.prefix, next_hop),
                "NC 授权网段与 WSL2 转发网络冲突"
            );
        }

        let on_link = on_link_route(local_host, next_hop)?;
        let mut owner = Self {
            next_hop,
            local_host,
            rows: Vec::with_capacity(routes.len()),
        };
        for cidr in routes {
            if let Err(error) = owner.add(cidr, &on_link) {
                return match owner.remove() {
                    Ok(()) => Err(error),
                    Err(rollback) => {
                        Err(error.context(format!("回滚 Windows NC 路由失败：{rollback:#}")))
                    }
                };
            }
        }
        Ok(owner)
    }

    fn add(&mut self, route: &Ipv4Cidr, interface: &MIB_IPFORWARD_ROW2) -> Result<()> {
        ensure!(
            !prefix_exists(route)?,
            "Windows 已有同一 IPv4 前缀的路由，无法接入 NC 隧道"
        );
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row) };
        row.InterfaceLuid = interface.InterfaceLuid;
        row.InterfaceIndex = interface.InterfaceIndex;
        row.DestinationPrefix = IP_ADDRESS_PREFIX {
            Prefix: sockaddr(route.network),
            PrefixLength: route.prefix,
        };
        row.NextHop = sockaddr(self.next_hop);
        row.SitePrefixLength = route.prefix;
        row.ValidLifetime = LEASE_SECONDS;
        row.PreferredLifetime = LEASE_SECONDS;
        row.Protocol = MIB_IPPROTO_NETMGMT;
        row.Metric = 0;
        row.Loopback = false;
        row.AutoconfigureAddress = false;
        row.Publish = false;
        row.Immortal = false;

        check(unsafe { CreateIpForwardEntry2(&row) }).context("无法安装 Windows NC 路由")?;
        self.rows.push(row);
        let created = lookup(row)?.context("Windows 未返回刚安装的 NC 路由")?;
        *self.rows.last_mut().expect("row was just installed") = created;
        ensure!(uses_lease(&created), "Windows 未对新 NC 路由启用有限有效期");
        Ok(())
    }

    pub(crate) fn renew(&mut self) -> Result<()> {
        if self.rows.is_empty() {
            return Ok(());
        }
        let link = on_link_route(self.local_host, self.next_hop)?;
        for owned in &mut self.rows {
            let mut row = lookup(*owned)?.context("本次会话的 Windows NC 路由已失效")?;
            ensure!(
                same_interface(&row, &link) && matches_owned(&row, owned),
                "Windows NC 路由或 WSL2 网卡已被其他程序修改"
            );
            row.ValidLifetime = LEASE_SECONDS;
            row.PreferredLifetime = LEASE_SECONDS;
            check(unsafe { SetIpForwardEntry2(&row) }).context("无法续期 Windows NC 路由")?;
            // Subsequent cleanup can still recognize the row when read-back fails.
            *owned = row;
            let updated = lookup(row)?.context("续期后未找到 Windows NC 路由")?;
            if matches_attributes(&updated, &row) {
                // If the network stack changed lease semantics, remember the
                // resulting row so disconnect can remove that route as well.
                *owned = updated;
            }
            ensure!(
                matches_owned(&updated, &row) && uses_lease(&updated),
                "Windows 未应用 NC 路由续期"
            );
        }
        Ok(())
    }

    pub(crate) fn remove(&mut self) -> Result<()> {
        let mut first_error = None;
        self.rows.retain(|owned| match remove_owned(*owned) {
            Ok(()) => false,
            Err(error) => {
                first_error.get_or_insert(error);
                true
            }
        });
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for Routes {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

fn remove_owned(owned: MIB_IPFORWARD_ROW2) -> Result<()> {
    let Some(current) = lookup(owned)? else {
        return Ok(());
    };
    ensure!(
        matches_owned(&current, &owned),
        "Windows NC 路由已变化，已保留当前路由"
    );
    let status = unsafe { DeleteIpForwardEntry2(&current) };
    if is_missing(status) {
        return Ok(());
    }
    check(status).context("无法卸载本次会话安装的 Windows NC 路由")
}

fn lookup(mut row: MIB_IPFORWARD_ROW2) -> Result<Option<MIB_IPFORWARD_ROW2>> {
    let status = unsafe { GetIpForwardEntry2(&mut row) };
    if is_missing(status) {
        return Ok(None);
    }
    check(status).context("无法读取 Windows NC 路由")?;
    Ok(Some(row))
}

fn uses_lease(row: &MIB_IPFORWARD_ROW2) -> bool {
    !row.Immortal
        && (1..=LEASE_SECONDS).contains(&row.ValidLifetime)
        && row.PreferredLifetime <= row.ValidLifetime
}

fn matches_owned(row: &MIB_IPFORWARD_ROW2, owned: &MIB_IPFORWARD_ROW2) -> bool {
    matches_attributes(row, owned)
        && row.Immortal == owned.Immortal
        && row.ValidLifetime <= owned.ValidLifetime
        && row.PreferredLifetime <= owned.PreferredLifetime
}

fn matches_attributes(row: &MIB_IPFORWARD_ROW2, owned: &MIB_IPFORWARD_ROW2) -> bool {
    same_interface(row, owned)
        && row.Metric == owned.Metric
        && row.Protocol == owned.Protocol
        && row.Origin == owned.Origin
        && row.SitePrefixLength == owned.SitePrefixLength
        && row.Loopback == owned.Loopback
        && row.Publish == owned.Publish
        && row.AutoconfigureAddress == owned.AutoconfigureAddress
}

fn same_interface(a: &MIB_IPFORWARD_ROW2, b: &MIB_IPFORWARD_ROW2) -> bool {
    a.InterfaceIndex == b.InterfaceIndex
        && unsafe { a.InterfaceLuid.Value == b.InterfaceLuid.Value }
}

fn on_link_route(local_host: Ipv4Addr, next_hop: Ipv4Addr) -> Result<MIB_IPFORWARD_ROW2> {
    let interface = find_interface(local_host, next_hop)?;
    let mut best = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    check(unsafe {
        GetBestRoute2(
            &interface.InterfaceLuid,
            interface.InterfaceIndex,
            &sockaddr(local_host),
            &sockaddr(next_hop),
            0,
            &mut best,
            &mut source,
        )
    })
    .context("无法核对 Windows 到 WSL2 对端的路由")?;
    ensure!(
        best.InterfaceIndex == interface.InterfaceIndex
            && unsafe { best.InterfaceLuid.Value == interface.InterfaceLuid.Value }
            && ipv4(&best.NextHop) == Some(Ipv4Addr::UNSPECIFIED)
            && ipv4(&source) == Some(local_host)
            && !best.Loopback,
        "Windows 到 WSL2 对端不是同接口直连路由"
    );
    Ok(best)
}

fn find_interface(local_host: Ipv4Addr, next_hop: Ipv4Addr) -> Result<MIB_UNICASTIPADDRESS_ROW> {
    let mut table = MibTable::<MIB_UNICASTIPADDRESS_TABLE>(ptr::null_mut());
    check(unsafe { GetUnicastIpAddressTable(AF_INET, &mut table.0) })
        .context("无法读取 Windows IPv4 接口地址")?;
    ensure!(!table.0.is_null(), "Windows 未返回 IPv4 接口地址表");
    // The SDK's C layout includes padding before the first variable-length row.
    let rows = unsafe {
        slice::from_raw_parts(
            ptr::addr_of!((*table.0).Table).cast::<MIB_UNICASTIPADDRESS_ROW>(),
            (*table.0).NumEntries as usize,
        )
    };
    let mut candidates = rows.iter().filter(|row| {
        row.InterfaceIndex != 0
            && row.DadState == IpDadStatePreferred
            && !row.SkipAsSource
            && ipv4(&row.Address) == Some(local_host)
            && (1..=31).contains(&row.OnLinkPrefixLength)
            && u32::from(local_host) & mask(row.OnLinkPrefixLength)
                == u32::from(next_hop) & mask(row.OnLinkPrefixLength)
    });
    let selected = *candidates
        .next()
        .context("未找到连接到 WSL2 对端的 Windows IPv4 接口")?;
    ensure!(
        candidates.next().is_none(),
        "Windows 上存在多个匹配的 WSL2 直连接口"
    );
    Ok(selected)
}

fn prefix_exists(route: &Ipv4Cidr) -> Result<bool> {
    let mut table = MibTable::<MIB_IPFORWARD_TABLE2>(ptr::null_mut());
    let status = unsafe { GetIpForwardTable2(AF_INET, &mut table.0) };
    if status == ERROR_NOT_FOUND {
        return Ok(false);
    }
    check(status).context("无法读取 Windows IPv4 路由表")?;
    ensure!(!table.0.is_null(), "Windows 未返回 IPv4 路由表");
    let rows = unsafe {
        slice::from_raw_parts(
            ptr::addr_of!((*table.0).Table).cast::<MIB_IPFORWARD_ROW2>(),
            (*table.0).NumEntries as usize,
        )
    };
    Ok(rows.iter().any(|row| {
        row.DestinationPrefix.PrefixLength == route.prefix
            && ipv4(&row.DestinationPrefix.Prefix) == Some(route.network)
    }))
}

struct MibTable<T>(*mut T);

impl<T> Drop for MibTable<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { FreeMibTable(self.0.cast()) };
        }
    }
}

fn sockaddr(address: Ipv4Addr) -> SOCKADDR_INET {
    SOCKADDR_INET {
        Ipv4: SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(address.octets()),
                },
            },
            sin_zero: [0; 8],
        },
    }
}

fn ipv4(address: &SOCKADDR_INET) -> Option<Ipv4Addr> {
    (unsafe { address.si_family } == AF_INET)
        .then(|| Ipv4Addr::from(unsafe { address.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes()))
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn contains(network: Ipv4Addr, prefix: u8, address: Ipv4Addr) -> bool {
    u32::from(address) & mask(prefix) == u32::from(network)
}

fn is_unicast(address: Ipv4Addr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_multicast()
        && !address.is_broadcast()
}

fn is_missing(status: WIN32_ERROR) -> bool {
    matches!(status, ERROR_NOT_FOUND | ERROR_FILE_NOT_FOUND)
}

fn check(status: WIN32_ERROR) -> io::Result<()> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}
