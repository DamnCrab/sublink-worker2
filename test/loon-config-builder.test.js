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
});
