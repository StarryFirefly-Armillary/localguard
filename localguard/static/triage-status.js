/* Advisory triage status mapping for the UI.
 * Pure functions, no DOM. Exposed as window.TriageStatus when loaded in a
 * browser and via module.exports for Node tests.
 *
 * Legacy audits have no triage_status: derive it from verdict so old records
 * remain filterable/badged exactly like new ones.
 */
(function (root) {
  'use strict';

  function statusOf(triage) {
    if (!triage) return 'none';
    if (triage.triage_status === 'scored' || triage.triage_status === 'uncertain' ||
        triage.triage_status === 'abstained') return triage.triage_status;
    // legacy: no triage_status field
    if (triage.verdict === 'uncertain') return 'uncertain';
    if (triage.verdict === 'likely_true' || triage.verdict === 'likely_false') return 'scored';
    return 'abstained';
  }

  // Filter key: scored records must keep matching the likely_true/likely_false
  // dropdown options; uncertain/abstained match their own options.
  function filterKeyOf(triage) {
    if (!triage) return 'none';
    const status = statusOf(triage);
    return status === 'scored' ? triage.verdict : status;
  }

  // Badge CSS class suffix + label. scored uses the verdict so the existing
  // triage-likely_true / triage-likely_false colors still apply.
  function badgeOf(triage) {
    if (!triage) return null;
    const status = statusOf(triage);
    const key = status === 'scored' ? triage.verdict : status;
    const labels = {
      likely_true: '模型：可能是真的', likely_false: '模型：可能误报',
      scored: '模型：已判定', uncertain: '模型：不确定',
      abstained: '模型未判定，需人工复核',
    };
    return { status: status, key: key, label: labels[key] || '模型分诊' };
  }

  const api = { statusOf: statusOf, filterKeyOf: filterKeyOf, badgeOf: badgeOf };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root) root.TriageStatus = api;
})(typeof window !== 'undefined' ? window : null);
