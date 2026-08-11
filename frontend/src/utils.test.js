import { describe, expect, it } from 'vitest'
import {
  formatBytes,
  formatDelay,
  formatSpeed,
  formatUptime,
  maskSubscription,
  manualNodeToForm,
  nodeTypeDefaults,
  protocolLabel,
  validateHysteria2Obfs,
  validateNodeTag,
  validatePassword,
  validatePort,
  validateServer,
  validateSubscriptionUrl,
  validateTransport,
  validateUuid,
  validateVlessFlow,
  buildTransportPayload,
} from './utils.js'

describe('formatters', () => {
  it('formats uptime and throughput values', () => {
    expect(formatUptime(0)).toBe('--')
    expect(formatUptime(65)).toBe('1m 5s')
    expect(formatSpeed(1536)).toBe('1.5 KB/s')
    expect(formatBytes(1048576)).toBe('1.0 MB')
    expect(formatDelay(-1)).toBe('超时')
  })

  it('normalizes protocol labels and subscription display text', () => {
    expect(protocolLabel('ss')).toBe('shadowsocks')
    expect(protocolLabel('vmess')).toBe('vmess')
    expect(protocolLabel('vless')).toBe('vless')
    expect(protocolLabel('trojan')).toBe('trojan')
    expect(protocolLabel('tuic')).toBe('tuic')
    expect(protocolLabel('hysteria2')).toBe('hysteria2')
    expect(maskSubscription('https://example.com/path/to/token123456')).toBe('example.com...en123456')
  })
})

describe('validation', () => {
  it('accepts valid subscription URLs and node fields', () => {
    expect(validateSubscriptionUrl('https://example.com/sub?token=abc')).toBeNull()
    expect(validateNodeTag('香港节点 01')).toBeNull()
    expect(validateServer('node.example.com')).toBeNull()
    expect(validatePort(443)).toBeNull()
    expect(validatePassword('password123')).toBeNull()
    expect(validateUuid('123e4567-e89b-12d3-a456-426614174000')).toBeNull()
    expect(validateTransport('ws', '/path', 'example.com', '')).toBeNull()
    expect(validateVlessFlow('xtls-rprx-vision')).toBeNull()
    expect(validateHysteria2Obfs('salamander', 'obfs-secret')).toBeNull()
  })

  it('rejects invalid subscription URLs and node fields', () => {
    expect(validateSubscriptionUrl('ftp://example.com/sub')).toMatch(/HTTP/)
    expect(validateNodeTag('bad/tag')).toMatch(/只能包含/)
    expect(validateServer('localhost')).toMatch(/点号/)
    expect(validatePort(70000)).toMatch(/范围/)
    expect(validatePassword('short')).toMatch(/太短/)
    expect(validateUuid('not-a-uuid')).toMatch(/UUID/)
    expect(validateTransport('xhttp', '', '', '')).toMatch(/传输层/)
    expect(validateTransport('ws', 'path', '', '')).toMatch(/\//)
    expect(validateTransport('grpc', 'path', 'bad host', 'service')).toBeNull()
    expect(validateVlessFlow('bad-flow')).toMatch(/VLESS/)
    expect(validateHysteria2Obfs('', 'secret')).toMatch(/请先选择/)
  })
})

describe('payload helpers', () => {
  it('uses protocol-specific ports for fresh manual node forms', () => {
    expect(nodeTypeDefaults('socks').server_port).toBe(1080)
    expect(nodeTypeDefaults('http').server_port).toBe(8080)
    expect(nodeTypeDefaults('vless').server_port).toBe(443)
  })

  it('restores a VLESS manual node with TLS, Reality, and WebSocket fields', () => {
    const { nodeType, form } = manualNodeToForm({
      tag: 'edge',
      node_type: 'vless',
      outbound: {
        type: 'vless',
        tag: 'edge',
        server: 'edge.example.com',
        server_port: 8443,
        uuid: '123e4567-e89b-12d3-a456-426614174000',
        flow: 'xtls-rprx-vision',
        packet_encoding: 'xudp',
        tls: {
          enabled: true,
          server_name: 'origin.example.com',
          insecure: true,
          alpn: ['h2', 'http/1.1'],
          utls: { enabled: true, fingerprint: 'chrome' },
          reality: { enabled: true, public_key: 'public-key', short_id: 'abcd' },
        },
        transport: {
          type: 'ws',
          path: '/socket',
          headers: { Host: 'cdn.example.com' },
        },
      },
    })

    expect(nodeType).toBe('vless')
    expect(form).toMatchObject({
      tag: 'edge',
      server: 'edge.example.com',
      server_port: 8443,
      uuid: '123e4567-e89b-12d3-a456-426614174000',
      flow: 'xtls-rprx-vision',
      packet_encoding: 'xudp',
      tls_enabled: true,
      sni: 'origin.example.com',
      skip_cert_verify: true,
      alpn: 'h2, http/1.1',
      client_fingerprint: 'chrome',
      reality_public_key: 'public-key',
      reality_short_id: 'abcd',
      transport_type: 'ws',
      transport_path: '/socket',
      transport_host: 'cdn.example.com',
    })
  })

  it('restores protocol-specific Shadowsocks and VMess fields', () => {
    const shadowsocks = manualNodeToForm({
      outbound: {
        type: 'shadowsocks',
        tag: 'ss-node',
        server: 'ss.example.com',
        server_port: 8388,
        method: 'aes-256-gcm',
        password: 'password123',
      },
    })
    const vmess = manualNodeToForm({
      outbound: {
        type: 'vmess',
        tag: 'vmess-node',
        server: 'vmess.example.com',
        server_port: 443,
        uuid: '123e4567-e89b-12d3-a456-426614174000',
        security: 'none',
        alter_id: 4,
        transport: { type: 'grpc', service_name: 'proxy-service' },
      },
    })

    expect(shadowsocks.nodeType).toBe('ss')
    expect(shadowsocks.form).toMatchObject({ cipher: 'aes-256-gcm', password: 'password123' })
    expect(vmess.nodeType).toBe('vmess')
    expect(vmess.form).toMatchObject({
      vmess_cipher: 'none',
      alter_id: 4,
      tls_enabled: false,
      transport_type: 'grpc',
      grpc_service_name: 'proxy-service',
    })
  })

  it('drops stale transport fields for the selected transport type', () => {
    expect(buildTransportPayload({
      transport_type: 'grpc',
      transport_path: 'path',
      transport_host: 'bad host',
      grpc_service_name: ' service ',
    })).toEqual({
      transport_type: 'grpc',
      grpc_service_name: 'service',
    })

    expect(buildTransportPayload({
      transport_type: 'tcp',
      transport_path: '/ws',
      transport_host: 'example.com',
      grpc_service_name: 'service',
    })).toEqual({
      transport_type: 'tcp',
    })
  })

  it('keeps path transport fields and drops gRPC service name', () => {
    expect(buildTransportPayload({
      transport_type: 'ws',
      transport_path: ' /ws ',
      transport_host: ' cdn.example.com ',
      grpc_service_name: 'service',
    })).toEqual({
      transport_type: 'ws',
      transport_path: '/ws',
      transport_host: 'cdn.example.com',
    })
  })
})
