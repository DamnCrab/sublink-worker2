import { SurgeConfigBuilder } from './SurgeConfigBuilder.js';

export class LoonConfigBuilder extends SurgeConfigBuilder {
    constructor(inputString, selectedRules, customRules, baseConfig, lang, userAgent, groupByCountry) {
        super(inputString, selectedRules, customRules, baseConfig, lang, userAgent, groupByCountry);
    }

    convertProxy(proxy) {
        let loonProxy;
        switch (proxy.type) {
            case 'shadowsocks':
            case 'ss':
                // Loon: Tag = Shadowsocks, server, port, method, "password"
                loonProxy = `${proxy.tag} = Shadowsocks, ${proxy.server}, ${proxy.server_port}, ${proxy.method}, "${proxy.password}"`;
                if (proxy.udp) {
                    loonProxy += `, udp=true`;
                }
                if (proxy.plugin === 'obfs') {
                    // Supported: simple-obfs
                    // Loon format: obfs-name=http|tls, obfs-host=..., obfs-uri=...
                    // Assuming proxy.plugin_opts contains the details
                    if (proxy.plugin_opts) {
                        if (proxy.plugin_opts.mode) loonProxy += `, obfs-name=${proxy.plugin_opts.mode}`;
                        if (proxy.plugin_opts.host) loonProxy += `, obfs-host=${proxy.plugin_opts.host}`;
                        // Loon uses obfs-uri, simple-obfs usually uses obfs-uri or nothing?
                    }
                }
                break;

            case 'vmess':
                // Loon: Tag = vmess, server, port, encryption, "uuid", ...
                const cipher = proxy.security || proxy.method || 'auto';
                loonProxy = `${proxy.tag} = vmess, ${proxy.server}, ${proxy.server_port}, ${cipher}, "${proxy.uuid}"`;

                // Transport
                if (proxy.transport?.type === 'ws') {
                    loonProxy += ', transport=ws';
                    if (proxy.transport.path) loonProxy += `, path=${proxy.transport.path}`;
                    if (proxy.transport.headers?.Host) loonProxy += `, host=${proxy.transport.headers.Host}`;
                } else if (proxy.transport?.type === 'http') {
                    loonProxy += ', transport=http';
                    if (proxy.transport.path) loonProxy += `, path=${proxy.transport.path}`;
                    if (proxy.transport.headers?.Host) loonProxy += `, host=${proxy.transport.headers.Host}`;
                } else {
                    loonProxy += ', transport=tcp';
                }

                // TLS
                if (proxy.tls?.enabled) {
                    loonProxy += ', over-tls=true';
                    if (proxy.tls.server_name) loonProxy += `, sni=${proxy.tls.server_name}`;
                    if (proxy.tls.insecure) loonProxy += `, skip-cert-verify=true`;
                } else {
                    loonProxy += ', over-tls=false';
                }

                if (proxy.alter_id !== undefined) {
                    loonProxy += `, alterId=${proxy.alter_id}`;
                }
                if (proxy.udp) {
                    loonProxy += `, udp=true`;
                }
                break;

            case 'trojan':
                // Loon: Tag = trojan, server, port, "password"
                loonProxy = `${proxy.tag} = trojan, ${proxy.server}, ${proxy.server_port}, "${proxy.password}"`;

                if (proxy.tls?.server_name) {
                    loonProxy += `, sni=${proxy.tls.server_name}`;
                }
                if (proxy.tls?.insecure) {
                    loonProxy += `, skip-cert-verify=true`;
                }
                // Loon trojan supports ws?
                if (proxy.transport?.type === 'ws') {
                    loonProxy += `, transport=ws`;
                    if (proxy.transport.path) loonProxy += `, path=${proxy.transport.path}`;
                    if (proxy.transport.headers?.Host) loonProxy += `, host=${proxy.transport.headers.Host}`;
                }
                if (proxy.udp) {
                    loonProxy += `, udp=true`;
                }
                break;

            case 'hysteria2':
                // Loon: Tag = Hysteria2, server, port, "password", ...
                loonProxy = `${proxy.tag} = Hysteria2, ${proxy.server}, ${proxy.server_port}, "${proxy.password}"`;
                if (proxy.tls?.server_name) {
                    loonProxy += `, sni=${proxy.tls.server_name}`;
                }
                if (proxy.tls?.insecure) {
                    loonProxy += `, skip-cert-verify=true`;
                }
                if (proxy.udp) {
                    loonProxy += `, udp=true`;
                }
                // obfs? Loon docs mention salamander-password
                if (proxy.obfs?.type === 'salamander') {
                    if (proxy.obfs.password) loonProxy += `, salamander-password=${proxy.obfs.password}`;
                }
                break;

            default:
                // Fallback to Surge format for other types if they happen to be compatible or just comment it out
                // Loon supports http, https, socks5, wireguard too.
                // Assuming SurgeConfigBuilder.convertProxy might produce Surge format which might not be compatible if Loon is strict.
                // But for now let's rely on specific overrides.
                return super.convertProxy(proxy);
        }
        return loonProxy;
    }
}
