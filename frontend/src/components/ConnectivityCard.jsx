import { Play, Globe, LoaderCircle } from 'lucide-react'
import { Button, SectionCard } from './ui.jsx'
import { classNames, CONNECTIVITY_SITES, getDelayTone } from '../utils.js'
import { useI18n } from '../i18n.jsx'

export function ConnectivityCard({
  connectivityResults,
  testingConnectivity,
  currentTestingSite,
  status,
  onTestAll,
  onStopTest,
  onTestSingleSite
}) {
  const { t } = useI18n()
  return (
    <SectionCard
      bodyClassName="panel-body-tight"
      header={
        <div className="section-header">
          <div className="section-title-wrap">
            <Globe size={14} className="section-icon" />
            <span>{t('conn.title')}</span>
          </div>
          <Button
            tone="secondary"
            size="sm"
            icon={testingConnectivity ? <LoaderCircle size={11} className="spin" /> : <Play size={11} />}
            loading={testingConnectivity}
            disabled={status.initializing}
            onClick={testingConnectivity ? onStopTest : onTestAll}
          >
            {testingConnectivity ? t('conn.stop') : t('conn.start')}
          </Button>
        </div>
      }
    >
      <div className="connectivity-grid">
        {CONNECTIVITY_SITES.map((site) => {
          const result = connectivityResults[site.name]
          const tone = result ? (result.success ? getDelayTone(result.latency_ms) : 'timeout') : ''
          const isTesting = currentTestingSite === site.name
          return (
            <button
              key={site.name}
              className={classNames('connectivity-item', tone, isTesting && 'testing')}
              onClick={() => !currentTestingSite && onTestSingleSite(site)}
              disabled={Boolean(currentTestingSite)}
            >
              <div className="connectivity-copy">
                <span>{site.name}</span>
                <span>{result ? (result.success ? `${result.latency_ms}ms` : t('conn.timeout')) : '--'}</span>
              </div>
            </button>
          )
        })}
      </div>
    </SectionCard>
  )
}
