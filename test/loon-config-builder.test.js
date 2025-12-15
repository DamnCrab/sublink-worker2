import { describe, it, expect } from 'vitest';
import { LoonConfigBuilder } from '../src/builders/LoonConfigBuilder.js';

describe('LoonConfigBuilder', () => {
    it('should convert Shadowsocks proxy correctly', () => {
        const builder = new LoonConfigBuilder();
        const proxy = {
            tag: 'SS Node',
            type: 'shadowsocks',
            server: 'example.com',
            server_port: 443,
            method: 'aes-128-gcm',
            password: 'password',
            udp: true
        };
        const result = builder.convertProxy(proxy);
        expect(result).toBe('SS Node = Shadowsocks, example.com, 443, aes-128-gcm, "password", udp=true');
    });

    it('should convert VMess proxy correctly', () => {
        const builder = new LoonConfigBuilder();
        const proxy = {
            tag: 'VMess Node',
            type: 'vmess',
            server: 'example.com',
            server_port: 10086,
            uuid: 'uuid-123',
            alter_id: 0,
            security: 'auto',
            udp: true,
            tls: {
                enabled: true,
                server_name: 'example.com',
                insecure: true
            },
            transport: {
                type: 'ws',
                path: '/ws',
                headers: {
                    Host: 'host.com'
                }
            }
        };
        const result = builder.convertProxy(proxy);
        // Expect: Tag = vmess, server, port, encryption, "uuid", transport=ws, path=..., host=..., over-tls=true, sni=..., skip-cert-verify=..., alterId=0, udp=true
        expect(result).toContain('VMess Node = vmess, example.com, 10086, auto, "uuid-123"');
        expect(result).toContain('transport=ws');
        expect(result).toContain('path=/ws');
        expect(result).toContain('host=host.com');
        expect(result).toContain('over-tls=true');
        expect(result).toContain('sni=example.com');
        expect(result).toContain('skip-cert-verify=true');
        expect(result).toContain('alterId=0');
        expect(result).toContain('udp=true');
    });

    it('should convert Trojan proxy correctly', () => {
        const builder = new LoonConfigBuilder();
        const proxy = {
            tag: 'Trojan Node',
            type: 'trojan',
            server: 'example.com',
            server_port: 443,
            password: 'password',
            udp: true,
            tls: {
                server_name: 'example.com',
                insecure: false
            }
        };
        const result = builder.convertProxy(proxy);
        expect(result).toBe('Trojan Node = trojan, example.com, 443, "password", sni=example.com, udp=true');
    });

    it('should convert VLESS proxy correctly', () => {
        const builder = new LoonConfigBuilder();
        const proxy = {
            tag: 'VLESS Node',
            type: 'vless',
            server: 'example.com',
            server_port: 443,
            uuid: 'uuid-vless',
            udp: true,
            transport: {
                type: 'ws',
                path: '/vless',
                headers: { Host: 'vless.com' }
            },
            tls: {
                enabled: true,
                server_name: 'vless.com',
                insecure: true,
                reality: {
                    enabled: true,
                    public_key: 'pk-123',
                    short_id: 'sid-123'
                }
            },
            flow: 'xtls-rprx-vision'
        };
        const result = builder.convertProxy(proxy);
        // Expect VLESS format
        expect(result).toContain('VLESS Node = VLESS, example.com, 443, "uuid-vless"');
        expect(result).toContain('transport=ws');
        expect(result).toContain('path=/vless');
        expect(result).toContain('host=vless.com');
        expect(result).toContain('over-tls=true');
        expect(result).toContain('sni=vless.com');
        expect(result).toContain('skip-cert-verify=true');
        expect(result).toContain('flow=xtls-rprx-vision');
        expect(result).toContain('public-key="pk-123"');
        expect(result).toContain('short-id=sid-123');
        expect(result).toContain('udp=true');
    });
});
