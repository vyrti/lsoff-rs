use crate::model::Proto;

/// Structure representing service display name and search aliases.
struct ServiceMeta {
    name: &'static str,
    aliases: &'static [&'static str],
}

/// Returns the primary display service name if known and unambiguous, or empty string.
#[must_use]
pub fn service_name(proto: Proto, port: u16) -> &'static str {
    get_meta(proto, port).map_or("", |m| m.name)
}

/// Returns lowercase aliases (including primary name) used for search filtering.
#[must_use]
pub fn search_terms(proto: Proto, port: u16) -> &'static [&'static str] {
    get_meta(proto, port).map_or(&[], |m| m.aliases)
}

const fn get_meta(proto: Proto, port: u16) -> Option<ServiceMeta> {
    match (proto, port) {
        (Proto::Tcp, 20) => Some(ServiceMeta {
            name: "ftp-data",
            aliases: &["ftp-data"],
        }),
        (Proto::Tcp, 21) => Some(ServiceMeta {
            name: "ftp",
            aliases: &["ftp"],
        }),
        (Proto::Tcp | Proto::Udp, 22) => Some(ServiceMeta {
            name: "ssh",
            aliases: &["ssh"],
        }),
        (Proto::Tcp, 23) => Some(ServiceMeta {
            name: "telnet",
            aliases: &["telnet"],
        }),
        (Proto::Tcp, 25) => Some(ServiceMeta {
            name: "smtp",
            aliases: &["smtp"],
        }),
        (Proto::Tcp | Proto::Udp, 53) => Some(ServiceMeta {
            name: "dns",
            aliases: &["dns", "domain"],
        }),
        (Proto::Udp, 67) => Some(ServiceMeta {
            name: "dhcp",
            aliases: &["dhcp", "bootps"],
        }),
        (Proto::Udp, 68) => Some(ServiceMeta {
            name: "dhcp-client",
            aliases: &["dhcp-client", "bootpc"],
        }),
        (Proto::Udp, 69) => Some(ServiceMeta {
            name: "tftp",
            aliases: &["tftp"],
        }),
        (Proto::Tcp, 80) => Some(ServiceMeta {
            name: "http",
            aliases: &["http"],
        }),
        (Proto::Tcp | Proto::Udp, 88) => Some(ServiceMeta {
            name: "kerberos",
            aliases: &["kerberos"],
        }),
        (Proto::Tcp, 110) => Some(ServiceMeta {
            name: "pop3",
            aliases: &["pop3"],
        }),
        (Proto::Tcp | Proto::Udp, 111) => Some(ServiceMeta {
            name: "rpcbind",
            aliases: &["rpcbind", "sunrpc"],
        }),
        (Proto::Tcp, 119) => Some(ServiceMeta {
            name: "nntp",
            aliases: &["nntp"],
        }),
        (Proto::Udp, 123) => Some(ServiceMeta {
            name: "ntp",
            aliases: &["ntp"],
        }),
        (Proto::Tcp | Proto::Udp, 135) => Some(ServiceMeta {
            name: "msrpc",
            aliases: &["msrpc"],
        }),
        (Proto::Udp, 137) => Some(ServiceMeta {
            name: "netbios-ns",
            aliases: &["netbios-ns"],
        }),
        (Proto::Udp, 138) => Some(ServiceMeta {
            name: "netbios-dgm",
            aliases: &["netbios-dgm"],
        }),
        (Proto::Tcp, 139) => Some(ServiceMeta {
            name: "netbios-ssn",
            aliases: &["netbios-ssn"],
        }),
        (Proto::Tcp, 143) => Some(ServiceMeta {
            name: "imap",
            aliases: &["imap"],
        }),
        (Proto::Udp, 161) => Some(ServiceMeta {
            name: "snmp",
            aliases: &["snmp"],
        }),
        (Proto::Udp, 162) => Some(ServiceMeta {
            name: "snmptrap",
            aliases: &["snmptrap"],
        }),
        (Proto::Tcp, 179) => Some(ServiceMeta {
            name: "bgp",
            aliases: &["bgp"],
        }),
        (Proto::Tcp, 389) => Some(ServiceMeta {
            name: "ldap",
            aliases: &["ldap"],
        }),
        (Proto::Tcp, 443) => Some(ServiceMeta {
            name: "https",
            aliases: &["https"],
        }),
        (Proto::Tcp, 445) => Some(ServiceMeta {
            name: "smb",
            aliases: &["smb", "microsoft-ds"],
        }),
        (Proto::Tcp, 465) => Some(ServiceMeta {
            name: "smtps",
            aliases: &["smtps"],
        }),
        (Proto::Udp, 500) => Some(ServiceMeta {
            name: "isakmp",
            aliases: &["isakmp"],
        }),
        (Proto::Udp, 514) => Some(ServiceMeta {
            name: "syslog",
            aliases: &["syslog"],
        }),
        (Proto::Tcp, 515) => Some(ServiceMeta {
            name: "lpd",
            aliases: &["lpd"],
        }),
        (Proto::Tcp, 548) => Some(ServiceMeta {
            name: "afp",
            aliases: &["afp"],
        }),
        (Proto::Tcp, 587) => Some(ServiceMeta {
            name: "submission",
            aliases: &["submission", "smtp"],
        }),
        (Proto::Tcp, 631) => Some(ServiceMeta {
            name: "ipp",
            aliases: &["ipp", "cups"],
        }),
        (Proto::Tcp, 636) => Some(ServiceMeta {
            name: "ldaps",
            aliases: &["ldaps"],
        }),
        (Proto::Tcp, 993) => Some(ServiceMeta {
            name: "imaps",
            aliases: &["imaps"],
        }),
        (Proto::Tcp, 995) => Some(ServiceMeta {
            name: "pop3s",
            aliases: &["pop3s"],
        }),
        (Proto::Udp, 5353) => Some(ServiceMeta {
            name: "mdns",
            aliases: &["mdns"],
        }),
        (Proto::Tcp, 5432) => Some(ServiceMeta {
            name: "postgres",
            aliases: &["postgres", "postgresql"],
        }),
        (Proto::Tcp, 3306) => Some(ServiceMeta {
            name: "mysql",
            aliases: &["mysql"],
        }),
        (Proto::Tcp, 1433) => Some(ServiceMeta {
            name: "mssql",
            aliases: &["mssql"],
        }),
        (Proto::Tcp, 1521) => Some(ServiceMeta {
            name: "oracle",
            aliases: &["oracle"],
        }),
        (Proto::Tcp, 2049) => Some(ServiceMeta {
            name: "nfs",
            aliases: &["nfs"],
        }),
        (Proto::Tcp, 2379) => Some(ServiceMeta {
            name: "etcd",
            aliases: &["etcd"],
        }),
        (Proto::Tcp, 2380) => Some(ServiceMeta {
            name: "etcd-peer",
            aliases: &["etcd-peer"],
        }),
        (Proto::Tcp, 3389) => Some(ServiceMeta {
            name: "rdp",
            aliases: &["rdp"],
        }),
        (Proto::Tcp, 5672) => Some(ServiceMeta {
            name: "amqp",
            aliases: &["amqp"],
        }),
        (Proto::Tcp, 5900) => Some(ServiceMeta {
            name: "vnc",
            aliases: &["vnc"],
        }),
        (Proto::Tcp, 6379) => Some(ServiceMeta {
            name: "redis",
            aliases: &["redis"],
        }),
        (Proto::Tcp, 8080) => Some(ServiceMeta {
            name: "http",
            aliases: &["http", "http-alt"],
        }),
        (Proto::Tcp, 8008) => Some(ServiceMeta {
            name: "http",
            aliases: &["http"],
        }),
        (Proto::Tcp, 8443) => Some(ServiceMeta {
            name: "https",
            aliases: &["https"],
        }),
        (Proto::Tcp, 9200) => Some(ServiceMeta {
            name: "elasticsearch",
            aliases: &["elasticsearch"],
        }),
        (Proto::Tcp, 11211) => Some(ServiceMeta {
            name: "memcached",
            aliases: &["memcached"],
        }),
        (Proto::Tcp, 27017) => Some(ServiceMeta {
            name: "mongodb",
            aliases: &["mongodb", "mongo"],
        }),
        (Proto::Tcp, 27018) => Some(ServiceMeta {
            name: "mongodb",
            aliases: &["mongodb"],
        }),
        (Proto::Tcp, 4222) => Some(ServiceMeta {
            name: "nats",
            aliases: &["nats"],
        }),
        (Proto::Tcp, 2375) => Some(ServiceMeta {
            name: "docker",
            aliases: &["docker"],
        }),
        (Proto::Tcp, 2376) => Some(ServiceMeta {
            name: "docker-tls",
            aliases: &["docker-tls"],
        }),
        (Proto::Tcp, 6443) => Some(ServiceMeta {
            name: "kubernetes",
            aliases: &["kubernetes", "k8s"],
        }),
        (Proto::Tcp, 10250) => Some(ServiceMeta {
            name: "kubelet",
            aliases: &["kubelet"],
        }),
        (Proto::Tcp, 5173 | 5174 | 24678) => Some(ServiceMeta {
            name: "vite",
            aliases: &["vite"],
        }),
        (Proto::Tcp, 9229) => Some(ServiceMeta {
            name: "node-inspect",
            aliases: &["node-inspect"],
        }),
        (Proto::Tcp, 7687) => Some(ServiceMeta {
            name: "neo4j",
            aliases: &["neo4j"],
        }),
        (Proto::Tcp, 8161) => Some(ServiceMeta {
            name: "activemq",
            aliases: &["activemq"],
        }),
        (Proto::Tcp, 9418) => Some(ServiceMeta {
            name: "git",
            aliases: &["git"],
        }),
        (Proto::Tcp, 853) => Some(ServiceMeta {
            name: "dot",
            aliases: &["dot", "dns-over-tls"],
        }),
        (Proto::Udp, 853) => Some(ServiceMeta {
            name: "doq",
            aliases: &["doq"],
        }),
        (Proto::Tcp, 8888) => Some(ServiceMeta {
            name: "jupyter",
            aliases: &["jupyter"],
        }),
        (Proto::Tcp, 4200) => Some(ServiceMeta {
            name: "angular",
            aliases: &["angular"],
        }),

        // Ambiguous display names: search aliases only
        (Proto::Tcp, 3000) => Some(ServiceMeta {
            name: "",
            aliases: &["rails", "grafana", "node"],
        }),
        (Proto::Tcp, 3001) => Some(ServiceMeta {
            name: "",
            aliases: &["react", "node"],
        }),
        (Proto::Tcp, 5000) => Some(ServiceMeta {
            name: "",
            aliases: &["flask", "airplay"],
        }),
        (Proto::Tcp, 8000) => Some(ServiceMeta {
            name: "",
            aliases: &["django", "deno"],
        }),
        (Proto::Tcp, 8081) => Some(ServiceMeta {
            name: "",
            aliases: &["http"],
        }),
        (Proto::Tcp, 9090) => Some(ServiceMeta {
            name: "",
            aliases: &["prometheus", "cockpit"],
        }),
        (Proto::Tcp, 9091) => Some(ServiceMeta {
            name: "",
            aliases: &["prometheus"],
        }),
        (Proto::Tcp, 16686) => Some(ServiceMeta {
            name: "",
            aliases: &["jaeger"],
        }),
        (Proto::Tcp, 4317 | 4318) => Some(ServiceMeta {
            name: "",
            aliases: &["otlp"],
        }),

        _ => None,
    }
}
