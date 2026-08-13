import { useEffect, useMemo, useState, useCallback } from 'react'
import {
  TopBar,
  StatusCard,
  ProxyCard,
  NodesCard,
  SubsCard,
  ProcessProxyCard,
  PoolCard,
  ConnectivityCard,
  ConfirmModal,
  ConnectionsModal,
  NodeModal,
  PoolTestResultModal,
  ToastStack,
  OnboardingScreen
} from './components/index.js'
import {
  useToast,
  useApi,
  useStatus,
  useSubs,
  useNodes,
  useNodeInventory,
  useProcessProxy,
  usePool,
  useProxies,
  useTraffic,
  useConnections,
  useVersion,
  useDelays,
  useConnectivity,
  usePolling
} from './hooks/index.js'
import {
  EMPTY_NODE_FORM,
  manualNodeToForm,
  nodeTypeDefaults,
  validateSubscriptionUrl,
  validateNodeTag,
  validateServer,
  validatePort,
  validatePassword,
  validateOptionalCredential,
  validateHysteria2Obfs,
  validateTransport,
  buildTransportPayload,
  validateUuid,
  validateVlessFlow,
  CONNECTIVITY_SITES,
  translateError,
} from './utils.js'
import { useI18n } from './i18n.jsx'

const CONNECTIONS_MODAL_MIN_WIDTH = 841

function hasProcessMatch(config) {
  const match = config?.match || {}
  return ['names', 'paths', 'path_regex'].some((key) => Array.isArray(match[key]) && match[key].length > 0)
}

export default function App() {
  const { t } = useI18n()
  const [firstLoadDone, setFirstLoadDone] = useState(false)
  const [loadingAction, setLoadingAction] = useState('')
  const [upgrading, setUpgrading] = useState(false)
  const [checkingVersion, setCheckingVersion] = useState(false)
  const [nodeForm, setNodeForm] = useState(EMPTY_NODE_FORM)
  const [nodeType, setNodeType] = useState('hysteria2')
  const [showNodeModal, setShowNodeModal] = useState(false)
  const [editingNodeTag, setEditingNodeTag] = useState(null)
  const [showConnectionsModal, setShowConnectionsModal] = useState(false)
  const [modeSetup, setModeSetup] = useState(null)
  const [confirmState, setConfirmState] = useState({ open: false, title: '', message: '', onConfirm: null })

  const clashApiBase = useMemo(() => '/api/clash', [])

  const { toasts, showToast } = useToast()
  const { apiCall } = useApi({ loadingAction, setLoadingAction })
  const { status, fetchStatus } = useStatus()
  const { subs, fetchSubs } = useSubs()
  const { nodes, fetchNodes } = useNodes()
  const { nodeInventory, setNodeInventory, fetchNodeInventory } = useNodeInventory()
  const { processProxy, setProcessProxy, fetchProcessProxy } = useProcessProxy()
  const {
    pool,
    setPool,
    poolEndpoints,
    fetchPool,
    fetchPoolEndpoints,
    testingPoolPort,
    poolTestResult,
    testPoolEndpoint,
    clearPoolTestResult,
  } = usePool(status.mode)
  const { primaryGroupName, primaryGroup, fetchProxies } = useProxies(status)
  const { traffic, closeSockets } = useTraffic(status)
  const {
    connectionsInfo,
    connectionsLoading,
    connectionsError,
    fetchConnections,
    closeConnection,
    closeAllConnections,
  } = useConnections(status, clashApiBase)
  const { versionInfo, fetchVersion } = useVersion()
  const { delays, testingNodes, testingGroup, testDelay, testGroupDelays } = useDelays()
  const { 
    connectivityResults, 
    testingConnectivity, 
    currentTestingSite,
    testSingleSite, 
    testAllConnectivity,
    stopConnectivity
  } = useConnectivity()

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const embedParam = params.get('embed')
    let embedded = false
    try {
      embedded = window.self !== window.top
    } catch {
      embedded = true
    }
    const embedMode = embedParam === '1' || embedParam === 'true' || embedded
    const root = document.documentElement
    if (embedMode) {
      root.setAttribute('data-embed-mode', 'true')
    } else {
      root.removeAttribute('data-embed-mode')
    }
    return () => {
      root.removeAttribute('data-embed-mode')
    }
  }, [])

  const nodeMetaMap = useMemo(() => {
    const map = new Map()
    nodeInventory.nodes.forEach((node) => map.set(node.tag, node))
    return map
  }, [nodeInventory.nodes])

  const cachedPrimaryGroup = useMemo(() => {
    const all = nodeInventory.nodes.map((node) => node.tag)
    return all.length > 0 ? { all, now: nodeInventory.current } : null
  }, [nodeInventory])
  const displayedPrimaryGroup = status.running && primaryGroup ? primaryGroup : cachedPrimaryGroup
  const displayedPrimaryGroupName = status.running && primaryGroupName ? primaryGroupName : 'proxy'
  const currentNodeMeta = displayedPrimaryGroup?.now
    ? nodeMetaMap.get(displayedPrimaryGroup.now)
    : null
  const proxyInteractive = status.running && Boolean(primaryGroup)

  const openConfirm = useCallback((title, message, onConfirm) => {
    setConfirmState({ open: true, title, message, onConfirm })
  }, [])

  const closeConfirm = useCallback(() => {
    setConfirmState({ open: false, title: '', message: '', onConfirm: null })
  }, [])

  const handleNodeTypeChange = useCallback((nextType) => {
    setNodeType(nextType)
  }, [])

  const handleOpenAddNode = useCallback(() => {
    setEditingNodeTag(null)
    setNodeForm({ ...EMPTY_NODE_FORM, ...nodeTypeDefaults(nodeType) })
    setShowNodeModal(true)
  }, [nodeType])

  const handleOpenEditNode = useCallback((node) => {
    const editor = manualNodeToForm(node)
    setEditingNodeTag(node.tag)
    setNodeType(editor.nodeType)
    setNodeForm(editor.form)
    setShowNodeModal(true)
  }, [])

  const handleCloseNodeModal = useCallback(() => {
    setShowNodeModal(false)
    setEditingNodeTag(null)
  }, [])

  // 首次加载：获取初始状态后再决定显示 onboarding 还是 dashboard
  useEffect(() => {
    Promise.all([
      fetchStatus(),
      fetchSubs(),
      fetchNodes(),
      fetchNodeInventory(),
      fetchProcessProxy(),
      fetchPool(),
    ])
      .then(([initialStatus]) => fetchPoolEndpoints(initialStatus?.mode))
      .finally(() => setFirstLoadDone(true))
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const needsOnboarding = firstLoadDone
    && !status.initializing
    && !status.running
    && subs.length === 0
    && nodes.length === 0

  // 统一轮询管理：合并所有定时任务到单个定时器
  const pollingTasks = useMemo(() => {
    const tasks = [fetchStatus, fetchSubs, fetchNodes, fetchNodeInventory]
    // 服务运行时才轮询 proxies
    if (status.running) {
      tasks.push(fetchProxies)
    }
    return tasks
  }, [fetchStatus, fetchSubs, fetchNodes, fetchNodeInventory, fetchProxies, status.running])

  const connectionPollingTasks = useMemo(() => [fetchConnections], [fetchConnections])

  // 使用统一的轮询管理（始终启用，由 tasks 数组内部决定是否执行）
  usePolling(pollingTasks, true)
  usePolling(connectionPollingTasks, showConnectionsModal && status.running)

  // 始终获取版本信息；后端会在服务停止时仅返回当前版本而不检测更新
  useEffect(() => {
    fetchVersion()
  }, [status.running, fetchVersion])

  useEffect(() => {
    fetchPoolEndpoints(status.mode)
  }, [status.mode, status.running, fetchPoolEndpoints])

  // 清理 WebSocket 连接
  useEffect(() => {
    return () => closeSockets()
  }, [closeSockets])

  // Show warning toast when config has warning
  useEffect(() => {
    if (status.warning) {
      showToast(status.warning, 'error')
    }
  }, [status.warning, showToast])

  useEffect(() => {
    const mediaQuery = window.matchMedia(`(max-width: ${CONNECTIONS_MODAL_MIN_WIDTH - 1}px)`)
    const handleChange = () => {
      if (mediaQuery.matches) setShowConnectionsModal(false)
    }

    handleChange()
    mediaQuery.addEventListener('change', handleChange)
    return () => mediaQuery.removeEventListener('change', handleChange)
  }, [])

  const refreshProxyViews = useCallback(async () => {
    const tasks = [fetchNodeInventory(), fetchPoolEndpoints(status.mode)]
    if (status.running) tasks.push(fetchProxies())
    await Promise.all(tasks)
  }, [fetchNodeInventory, fetchPoolEndpoints, fetchProxies, status.mode, status.running])

  const handleToggleService = useCallback(async () => {
    try {
      if (status.running) {
        await apiCall('service/stop', { method: 'POST' }, 'stop')
        showToast(t('toast.serviceStopped'), 'success')
      } else {
        await apiCall('service/start', { method: 'POST' }, 'start')
        showToast(t('toast.serviceStarted'), 'success')
      }
      const nextStatus = await fetchStatus()
      const tasks = [fetchNodeInventory(), fetchPoolEndpoints(nextStatus?.mode || status.mode)]
      if (nextStatus?.running) tasks.push(fetchProxies())
      await Promise.all(tasks)
    } catch (error) {
      showToast(error.message, 'error')
    }
  }, [
    status.running,
    status.mode,
    apiCall,
    fetchStatus,
    fetchNodeInventory,
    fetchPoolEndpoints,
    fetchProxies,
    showToast,
    t,
  ])

  const applyProxyMode = useCallback(async (nextMode) => {
    try {
      const response = await apiCall(
        'mode',
        { method: 'POST', body: JSON.stringify({ mode: nextMode }) },
        'mode'
      )
      const nextStatus = await fetchStatus()
      const tasks = [fetchNodeInventory(), fetchPoolEndpoints(nextMode)]
      if (nextStatus?.running) tasks.push(fetchProxies())
      await Promise.all(tasks)
      setModeSetup(null)
      showToast(t('toast.modeSwitched', { mode: t(`mode.${nextMode}`) }), 'success')
      return response
    } catch (error) {
      showToast(error.message, 'error')
      return null
    }
  }, [
    apiCall,
    fetchStatus,
    fetchNodeInventory,
    fetchPoolEndpoints,
    fetchProxies,
    showToast,
    t,
  ])

  const handleSetMode = useCallback(async (nextMode) => {
    if (nextMode === status.mode) {
      setModeSetup(null)
      return
    }
    if (nextMode === 'process' && !hasProcessMatch(processProxy)) {
      setModeSetup('process')
      showToast(t('toast.fillProcessFirst'), 'info')
      return
    }

    setModeSetup(null)
    await applyProxyMode(nextMode)
  }, [status.mode, processProxy, applyProxyMode, showToast, t])

  const handleSaveProcessProxy = useCallback(async (nextConfig) => {
    try {
      const response = await apiCall(
        'tun-process',
        { method: 'POST', body: JSON.stringify(nextConfig) },
        'processProxy'
      )
      setProcessProxy(nextConfig)
      await Promise.all([fetchProcessProxy(), fetchStatus(), refreshProxyViews()])
      if (modeSetup === 'process') {
        await applyProxyMode('process')
      } else {
        showToast(response.message || t('toast.processSaved'), 'success')
      }
    } catch (error) {
      showToast(error.message, 'error')
    }
  }, [
    apiCall,
    setProcessProxy,
    fetchProcessProxy,
    fetchStatus,
    refreshProxyViews,
    modeSetup,
    applyProxyMode,
    showToast,
    t,
  ])

  const handleSavePool = useCallback(async (nextConfig) => {
    try {
      const response = await apiCall(
        'share',
        { method: 'POST', body: JSON.stringify(nextConfig) },
        'pool'
      )
      setPool(nextConfig)
      await Promise.all([
        fetchPool(),
        fetchStatus(),
        refreshProxyViews(),
      ])
      showToast(response.message || t('toast.poolSaved'), 'success')
    } catch (error) {
      showToast(error.message, 'error')
    }
  }, [
    apiCall,
    setPool,
    fetchPool,
    fetchStatus,
    refreshProxyViews,
    showToast,
    t,
  ])

  const handleSwitchProxy = useCallback(async (groupName, nodeName) => {
    if (!status.running) return
    try {
      const response = await fetch(`${clashApiBase}/proxies/${encodeURIComponent(groupName)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: nodeName }),
      })
      if (!response.ok) {
        const details = (await response.text()).trim()
        throw new Error(details || t('toast.switchFailedStatus', { status: response.status }))
      }
      await fetchProxies()
      setNodeInventory((previous) => ({ ...previous, current: nodeName }))
      fetch('/api/last-proxy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ group: groupName, name: nodeName }),
      }).catch((err) => console.warn('Failed to save last proxy:', err))
      showToast(t('toast.switchNode', { name: nodeName }), 'success')
    } catch {
      showToast(t('toast.switchFailed'), 'error')
    }
  }, [status.running, clashApiBase, fetchProxies, setNodeInventory, showToast, t])

  const handleAddSubscription = useCallback(async (input) => {
    const isContent = input.mode === 'content'
    if (!isContent) {
      const error = validateSubscriptionUrl(input.url)
      if (error) {
        showToast(translateError(t, error), 'error')
        return false
      }
    }

    try {
      await apiCall(
        isContent ? 'subs/content' : 'subs',
        {
          method: 'POST',
          body: JSON.stringify(
            isContent
              ? { content: input.content, name: input.name || null }
              : { url: input.url }
          ),
        },
        'addSub'
      )
      await Promise.all([fetchSubs(), refreshProxyViews()])
      showToast(t('toast.subAdded'), 'success')
      return true
    } catch (error) {
      showToast(error.message, 'error')
      return false
    }
  }, [apiCall, fetchSubs, refreshProxyViews, showToast, t])

  const handleDeleteSubscription = useCallback(async (url) => {
    try {
      await apiCall('subs', { method: 'DELETE', body: JSON.stringify({ url }) }, 'deleteSub')
      await Promise.all([fetchSubs(), refreshProxyViews()])
      showToast(t('toast.subDeleted'), 'success')
    } catch (error) {
      showToast(error.message, 'error')
    }
  }, [apiCall, fetchSubs, refreshProxyViews, showToast, t])

  const handleReplaceSubscription = useCallback(async (oldUrl, replacementUrl) => {
    const newUrl = replacementUrl.trim()
    const error = validateSubscriptionUrl(newUrl)
    if (error) {
      showToast(translateError(t, error), 'error')
      return false
    }
    if (newUrl === oldUrl) {
      showToast(t('toast.sameSubUrl'), 'error')
      return false
    }

    try {
      await apiCall(
        'subs',
        { method: 'PUT', body: JSON.stringify({ old_url: oldUrl, new_url: newUrl }) },
        'replaceSub'
      )
      await Promise.all([fetchSubs(), refreshProxyViews()])
      showToast(t('toast.subReplaced'), 'success')
      return true
    } catch (replaceError) {
      showToast(replaceError.message, 'error')
      return false
    }
  }, [apiCall, fetchSubs, refreshProxyViews, showToast, t])

  const handleRefreshSubscriptions = useCallback(async () => {
    try {
      const response = await apiCall('subs/refresh', { method: 'POST' }, 'refreshSubs')
      await Promise.all([fetchSubs(), refreshProxyViews()])
      const expired = /失效|expired/i.test(response.message || '')
      showToast(response.message || t('subs.refreshed'), expired ? 'info' : 'success')
    } catch (error) {
      showToast(error.message, 'error')
    }
  }, [apiCall, fetchSubs, refreshProxyViews, showToast, t])

  const handleSaveNode = useCallback(async () => {
    const isSimpleProxy = nodeType === 'socks' || nodeType === 'http'
    const requiresPassword = ['hysteria2', 'anytls', 'ss', 'trojan', 'tuic'].includes(nodeType)
    const requiresUuid = ['vmess', 'vless', 'tuic'].includes(nodeType)
    const supportsTransport = ['vmess', 'vless', 'trojan'].includes(nodeType)

    const tagError = validateNodeTag(nodeForm.tag)
    if (tagError) {
      showToast(translateError(t, tagError), 'error')
      return
    }
    const serverError = validateServer(nodeForm.server)
    if (serverError) {
      showToast(translateError(t, serverError), 'error')
      return
    }
    const portError = validatePort(nodeForm.server_port)
    if (portError) {
      showToast(translateError(t, portError), 'error')
      return
    }
    if (isSimpleProxy) {
      const passwordError = validateOptionalCredential(nodeForm.password, 'fields.password')
      if (passwordError) {
        showToast(translateError(t, passwordError), 'error')
        return
      }
      const usernameError = validateOptionalCredential(nodeForm.username, 'fields.username')
      if (usernameError) {
        showToast(translateError(t, usernameError), 'error')
        return
      }
    } else if (requiresPassword) {
      const passwordError = validatePassword(nodeForm.password)
      if (passwordError) {
        showToast(translateError(t, passwordError), 'error')
        return
      }
    }
    if (requiresUuid) {
      const uuidError = validateUuid(nodeForm.uuid)
      if (uuidError) {
        showToast(translateError(t, uuidError), 'error')
        return
      }
    }
    if (supportsTransport) {
      const transportError = validateTransport(
        nodeForm.transport_type,
        nodeForm.transport_path,
        nodeForm.transport_host,
        nodeForm.grpc_service_name,
      )
      if (transportError) {
        showToast(translateError(t, transportError), 'error')
        return
      }
    }
    if (nodeType === 'vless') {
      const flowError = validateVlessFlow(nodeForm.flow)
      if (flowError) {
        showToast(translateError(t, flowError), 'error')
        return
      }
      const hasRealityConfig = nodeForm.reality_public_key?.trim() || nodeForm.reality_short_id?.trim()
      if (hasRealityConfig && !nodeForm.client_fingerprint?.trim()) {
        showToast(t('node.realityNeedFingerprint'), 'error')
        return
      }
    }
    const obfsError = nodeType === 'hysteria2'
      ? validateHysteria2Obfs(nodeForm.obfs_type, nodeForm.obfs_password)
      : null
    if (obfsError) {
      showToast(translateError(t, obfsError), 'error')
      return
    }

    const payload = {
      node_type: nodeType,
      tag: nodeForm.tag.trim(),
      server: nodeForm.server.trim(),
      server_port: nodeForm.server_port,
    }

    if (isSimpleProxy) {
      if (nodeForm.username?.trim()) payload.username = nodeForm.username.trim()
      if (nodeForm.password?.trim()) payload.password = nodeForm.password.trim()
    } else if (requiresPassword) {
      payload.password = nodeForm.password.trim()
    }
    if (requiresUuid) payload.uuid = nodeForm.uuid.trim()

    if (nodeType === 'ss') {
      payload.cipher = nodeForm.cipher
    } else if (!isSimpleProxy) {
      if (nodeForm.sni?.trim()) payload.sni = nodeForm.sni.trim()
      payload.skip_cert_verify = nodeForm.skip_cert_verify
      const alpn = nodeForm.alpn.split(',').map((value) => value.trim()).filter(Boolean)
      if (alpn.length > 0) payload.alpn = alpn
      if (nodeForm.client_fingerprint?.trim()) payload.client_fingerprint = nodeForm.client_fingerprint.trim()
      if (nodeType === 'hysteria2' && nodeForm.obfs_type) {
        payload.obfs_type = nodeForm.obfs_type
        payload.obfs_password = nodeForm.obfs_password.trim()
      }
    }
    if (nodeType === 'vmess') {
      payload.cipher = nodeForm.vmess_cipher
      payload.alter_id = Number(nodeForm.alter_id || 0)
      payload.tls_enabled = Boolean(nodeForm.tls_enabled)
      if (nodeForm.packet_encoding) payload.packet_encoding = nodeForm.packet_encoding
    }
    if (nodeType === 'vless') {
      payload.tls_enabled = Boolean(nodeForm.tls_enabled)
      if (nodeForm.flow) payload.flow = nodeForm.flow
      if (nodeForm.packet_encoding) payload.packet_encoding = nodeForm.packet_encoding
      if (nodeForm.reality_public_key?.trim()) payload.reality_public_key = nodeForm.reality_public_key.trim()
      if (nodeForm.reality_short_id?.trim()) payload.reality_short_id = nodeForm.reality_short_id.trim()
    }
    if (supportsTransport) {
      Object.assign(payload, buildTransportPayload(nodeForm))
    }
    if (nodeType === 'tuic') {
      payload.tuic_congestion_control = nodeForm.tuic_congestion_control
      payload.tuic_udp_relay_mode = nodeForm.tuic_udp_relay_mode
      payload.tuic_zero_rtt = Boolean(nodeForm.tuic_zero_rtt)
    }

    try {
      const editing = editingNodeTag !== null
      const requestPayload = editing ? { original_tag: editingNodeTag, ...payload } : payload
      await apiCall(
        'nodes',
        { method: editing ? 'PUT' : 'POST', body: JSON.stringify(requestPayload) },
        editing ? 'updateNode' : 'addNode'
      )
      setShowNodeModal(false)
      setEditingNodeTag(null)
      setNodeForm({ ...EMPTY_NODE_FORM, ...nodeTypeDefaults(nodeType) })
      await Promise.all([fetchNodes(), refreshProxyViews()])
      showToast(editing ? t('toast.nodeUpdated') : t('toast.nodeAdded'), 'success')
    } catch (error) {
      showToast(error.message, 'error')
    }
  }, [nodeForm, nodeType, editingNodeTag, apiCall, fetchNodes, refreshProxyViews, showToast, t])

  const handleDeleteNode = useCallback(async (tag) => {
    try {
      await apiCall('nodes', { method: 'DELETE', body: JSON.stringify({ tag }) }, 'deleteNode')
      await Promise.all([fetchNodes(), refreshProxyViews()])
      showToast(t('toast.nodeDeleted'), 'success')
    } catch (error) {
      showToast(error.message, 'error')
    }
  }, [apiCall, fetchNodes, refreshProxyViews, showToast, t])

  const handleTestDelay = useCallback((nodeName) => {
    if (!status.running) return
    testDelay(clashApiBase, nodeName)
  }, [status.running, clashApiBase, testDelay])

  const handleTestGroupDelays = useCallback((groupName, nodeNames) => {
    if (!status.running) return
    testGroupDelays(clashApiBase, groupName, nodeNames)
  }, [status.running, clashApiBase, testGroupDelays])

  const handleTestSingleSite = useCallback((site) => {
    testSingleSite(site)
  }, [testSingleSite])

  const handleTestAllConnectivity = useCallback(() => {
    testAllConnectivity(CONNECTIVITY_SITES)
  }, [testAllConnectivity])

  const handleOpenConnections = useCallback(() => {
    if (window.matchMedia(`(max-width: ${CONNECTIONS_MODAL_MIN_WIDTH - 1}px)`).matches) {
      showToast(t('connections.mobileUnsupported'), 'info')
      return
    }

    setShowConnectionsModal(true)
    fetchConnections()
  }, [fetchConnections, showToast, t])

  const handleUpgradeClick = useCallback(async () => {
    if (!status.running) {
      showToast(t('toast.upgradeNeedRunning'), 'info')
      return
    }

    if (!versionInfo.has_update) {
      setCheckingVersion(true)
      try {
        const fresh = await fetchVersion()
        if (fresh?.has_update) {
          showToast(t('toast.updateFound', { version: fresh.latest }), 'success')
        } else {
          showToast(t('toast.upToDate'), 'info')
        }
      } finally {
        setCheckingVersion(false)
      }
      return
    }

    const targetVersion = versionInfo.latest
    const currentVersion = versionInfo.current
    openConfirm(
      t('confirm.upgradeTitle'),
      t('confirm.upgradeMessage', { current: currentVersion, target: targetVersion }),
      async () => {
      setUpgrading(true)
      try {
        const response = await fetch('/api/upgrade', { method: 'POST' })
        const payload = await response.json()
        if (!payload.success) throw new Error(payload.message || t('toast.upgradeFailed'))
        showToast(t('toast.upgradeSuccess'), 'success')
        for (let index = 0; index < 30; index += 1) {
          await new Promise((resolve) => window.setTimeout(resolve, 500))
          try {
            const ping = await fetch('/api/version')
            if (ping.ok) {
              const versionPayload = await ping.json()
              if (versionPayload.success && versionPayload.data?.current !== currentVersion) {
                window.location.reload()
                return
              }
            }
          } catch {
            // ignore
          }
        }
        showToast(t('toast.upgradeTimeout'), 'error')
      } catch (error) {
        showToast(error.message, 'error')
      } finally {
        setUpgrading(false)
      }
    })
  }, [status.running, versionInfo, fetchVersion, showToast, openConfirm, t])

  const handleOpenDeleteNodeConfirm = useCallback((tag) => {
    openConfirm(t('confirm.deleteNodeTitle'), t('confirm.deleteNodeMessage', { tag }), () => handleDeleteNode(tag))
  }, [openConfirm, handleDeleteNode, t])

  const handleOpenDeleteSubConfirm = useCallback((url, label) => {
    openConfirm(t('confirm.deleteSubTitle'), t('confirm.deleteSubMessage', { label }), () => handleDeleteSubscription(url))
  }, [openConfirm, handleDeleteSubscription, t])

  if (!firstLoadDone) {
    return <div className="shell"><div className="onboarding-loading">{t('app.loading')}</div></div>
  }

  if (needsOnboarding) {
    return (
      <div className="shell">
        <OnboardingScreen
          onAddSub={handleAddSubscription}
          loadingAction={loadingAction}
          onOpenAddNode={handleOpenAddNode}
        />
        <ToastStack toasts={toasts} />
        <NodeModal
          open={showNodeModal}
          editing={editingNodeTag !== null}
          nodeType={nodeType}
          setNodeType={handleNodeTypeChange}
          form={nodeForm}
          setForm={setNodeForm}
          loading={loadingAction === 'addNode' || loadingAction === 'updateNode'}
          onClose={handleCloseNodeModal}
          onSubmit={handleSaveNode}
        />
      </div>
    )
  }

  const displayedProxyMode = modeSetup || status.mode

  return (
    <div className="shell">
      <TopBar
        status={status}
        versionInfo={versionInfo}
        upgrading={upgrading}
        checkingVersion={checkingVersion}
        onUpgradeClick={handleUpgradeClick}
      />

      <main className="workspace">
        <StatusCard 
          status={status} 
          traffic={traffic} 
          loadingAction={loadingAction} 
          onToggleService={handleToggleService} 
          onSetMode={handleSetMode}
          onOpenConnections={handleOpenConnections}
        />

        <div className="content-grid">
          <div className="left-column">
            <ProxyCard
              status={status}
              primaryGroup={displayedPrimaryGroup}
              primaryGroupName={displayedPrimaryGroupName}
              interactive={proxyInteractive}
              currentNodeMeta={currentNodeMeta}
              delays={delays}
              testingNodes={testingNodes}
              testingGroup={testingGroup}
              onTestDelay={handleTestDelay}
              onTestGroupDelays={handleTestGroupDelays}
              onSwitchProxy={handleSwitchProxy}
              onOpenAddNode={handleOpenAddNode}
            />
          </div>

          <div className="right-column">
            <NodesCard 
              nodes={nodes} 
              onDeleteNode={handleOpenDeleteNodeConfirm} 
              onEditNode={handleOpenEditNode}
              onOpenAddNode={handleOpenAddNode}
            />

            <SubsCard
              subs={subs}
              loadingAction={loadingAction}
              onAddSub={handleAddSubscription}
              onDeleteSub={handleOpenDeleteSubConfirm}
              onReplaceSub={handleReplaceSubscription}
              onRefreshSubs={handleRefreshSubscriptions}
              isInitializing={status.initializing}
            />

            <ProcessProxyCard
              proxyMode={displayedProxyMode}
              config={processProxy}
              loading={loadingAction === 'processProxy'}
              disabled={status.initializing || loadingAction === 'mode'}
              onSave={handleSaveProcessProxy}
              showToast={showToast}
            />

            <PoolCard
              proxyMode={displayedProxyMode}
              config={pool}
              endpoints={poolEndpoints}
              loading={loadingAction === 'pool'}
              disabled={status.initializing || loadingAction === 'mode'}
              testingPort={testingPoolPort}
              onSave={handleSavePool}
              onTestEndpoint={testPoolEndpoint}
              showToast={showToast}
            />

            {displayedProxyMode !== 'pool' && (
              <ConnectivityCard
                connectivityResults={connectivityResults}
                testingConnectivity={testingConnectivity}
                currentTestingSite={currentTestingSite}
                status={status}
                onTestAll={handleTestAllConnectivity}
                onStopTest={stopConnectivity}
                onTestSingleSite={handleTestSingleSite}
              />
            )}
          </div>
        </div>
      </main>

      <ToastStack toasts={toasts} />

      <NodeModal 
        open={showNodeModal} 
        editing={editingNodeTag !== null}
        nodeType={nodeType} 
        setNodeType={handleNodeTypeChange}
        form={nodeForm} 
        setForm={setNodeForm} 
        loading={loadingAction === 'addNode' || loadingAction === 'updateNode'}
        onClose={handleCloseNodeModal}
        onSubmit={handleSaveNode}
      />

      <ConnectionsModal
        open={showConnectionsModal}
        status={status}
        data={connectionsInfo}
        loading={connectionsLoading}
        error={connectionsError}
        onClose={() => setShowConnectionsModal(false)}
        onRefresh={fetchConnections}
        onCloseConnection={closeConnection}
        onCloseAllConnections={closeAllConnections}
        showToast={showToast}
      />

      <PoolTestResultModal
        result={poolTestResult}
        onClose={clearPoolTestResult}
      />

      <ConfirmModal
        open={confirmState.open}
        title={confirmState.title}
        message={confirmState.message}
        onCancel={closeConfirm}
        onConfirm={() => {
          const action = confirmState.onConfirm
          closeConfirm()
          action?.()
        }}
      />
    </div>
  )
}
