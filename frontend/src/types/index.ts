export interface Threat {
  id: string
  full_name: string
  category: string
  layer: string
  severity: { level: string; score: number }
  event_count: number
  mitre_ics_ids: string[]
  affected_systems: string[]
  dataset_ref: string
}

export interface ThreatActor {
  id: string
  name: string
  nation_state: string
  category: string
  active_since: string
  motivation: string
  techniques: string[]
  target_sectors: string[]
  known_campaigns: string[]
  iocs: string[]
  tactic_breakdown: TacticCount[]
  technique_count: number
  description?: string
  aliases?: string[]
  first_observed?: string
  last_active?: string
}

export interface TacticCount {
  tactic_id: string
  tactic_name: string
  count: number
}

export interface MitreTactic {
  id: string
  name: string
  short_id: string
  order: number
  description?: string
}

export interface MitreTechnique {
  id: string
  name: string
  tactic_id: string
  tactic_name?: string
  description: string
  data_sources?: string[]
  platforms?: string[]
}

export interface Incident {
  id: string
  title: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  timestamp: string
  source: string
  category?: string
  actor?: string
  score?: number
  description?: string
}

export interface SOCMetrics {
  mttd_baseline: { value: number; unit: string }
  mttd_ml: { value: number; unit: string }
  mttr_baseline: { value: number; unit: string }
  mttr_ml: { value: number; unit: string }
  accuracy: { value: number; unit: string }
  fpr: { value: number; unit: string }
}

export interface NetworkNode {
  id: string
  label: string
  type: string
  purdue_level?: number
  sector?: string
  ip?: string
}

export interface NetworkLink {
  source: string
  target: string
  relation: string
}

export interface GeoCountry {
  code: string
  name: string
  role: 'origin' | 'target' | 'both'
  threat_score?: number
  targeting_actors?: string[]
  notable_incidents?: string[]
  notes?: string
}

export interface CVEEntry {
  cve: string
  vendor: string
  product: string
  cvss: number
  purdue_level: number
  kev: boolean
  description: string
}

export interface MLDetectionData {
  sensors: { name: string; base: number; unit: string }[]
  series: Record<string, number[]>
  anomaly_scores: number[]
  attack_labels: boolean[]
  comparisons: {
    window: number
    start_step: number
    end_step: number
    baseline_mttd: number
    ml_mttd: number
    improvement: number
  }[]
  roc_points: { fpr: number; tpr: number }[]
  accuracy: number
  false_positive_rate: number
  steps: number
}

export type TabId =
  | 'overview'
  | 'mitre'
  | 'scenarios'
  | 'correlation'
  | 'physical'
  | 'liveintel'
  | 'threatfeed'
  | 'actors'
  | 'news'
  | 'briefing'
  | 'soar'
  | 'heatmap'
  | 'network'
  | 'georisk'
  | 'killchain'
  | 'cvemap'
  | 'datasets'
  | 'references'
  | 'threatintel'
