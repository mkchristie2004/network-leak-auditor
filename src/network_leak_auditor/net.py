import ipaddress


def is_filtered_remote(remote_ip: str) -> bool:
    address = ipaddress.ip_address(remote_ip)
    return any(
        (
            address.is_loopback,
            address.is_link_local,
            address.is_multicast,
            address.is_private,
        )
    )
