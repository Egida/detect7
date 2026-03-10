<template>
  <div class="mt-3">
    <div class="row g-3 mb-3">
      <div class="col" v-for="s in stats" :key="s.label">
        <div class="stat-card">
          <div class="stat-label">{{ s.label }}</div>
          <div class="stat-value" :style="s.color ? {color: s.color} : {}">{{ s.value }}</div>
        </div>
      </div>
    </div>

    <div class="row g-3 mb-3">
      <div class="col-lg-6">
        <div class="chart-card"><h6>Requests</h6>
          <div class="chart-wrap" style="height:280px">
            <Line :data="timelineChart" :options="areaOpts" />
          </div>
        </div>
      </div>
      <div class="col-lg-6">
        <div class="chart-card"><h6>TOP Countries</h6>
          <div class="chart-wrap" style="height:280px">
            <Bar :data="countriesChart" :options="stackedBarOpts" />
          </div>
        </div>
      </div>
    </div>

    <div class="row g-3 mb-3">
      <div class="col-lg-6">
        <div class="chart-card"><h6>Problems</h6>
          <div class="chart-wrap" style="height:260px">
            <Bar :data="problemsChart" :options="barOpts" />
          </div>
        </div>
      </div>
      <div class="col-lg-6">
        <div class="chart-card"><h6>Problems RPS</h6>
          <div class="chart-wrap" style="height:260px">
            <Line :data="probRpsChart" :options="lineOpts" />
          </div>
        </div>
      </div>
    </div>

    <div class="row g-3 mb-3">
      <div class="col-lg-6">
        <div class="chart-card"><h6>Top Paths</h6>
          <div class="chart-wrap" style="height:260px">
            <Bar :data="pathsChart" :options="stackedBarOpts" />
          </div>
        </div>
      </div>
      <div class="col-lg-6">
        <div class="chart-card"><h6>Response Statuses</h6>
          <div class="chart-wrap" style="height:260px">
            <Bar :data="statusChart" :options="barOpts" />
          </div>
        </div>
      </div>
    </div>

    <div class="chart-card mb-3" v-if="dashboard.problem_ips && dashboard.problem_ips.length">
      <h6>Problem IPs</h6>
      <div class="table-responsive">
        <table class="table table-sm problem-table mb-0">
          <thead><tr>
            <th>Timestamp</th><th>IP</th><th>Country</th><th>PTR</th><th>RPS (max)</th><th>Requests</th>
          </tr></thead>
          <tbody>
            <tr v-for="(ip, i) in dashboard.problem_ips" :key="i">
              <td>{{ shortTs(ip.timestamp) }}</td>
              <td>{{ ip.detected_ip }}</td>
              <td>{{ ip.country || '-' }}</td>
              <td>{{ ip.ptr || '-' }}</td>
              <td>{{ ip.peak_rps }}</td>
              <td>{{ ip.request_count }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from "vue";
import { Bar, Line } from "vue-chartjs";
import {
  BarElement, CategoryScale, Chart as ChartJS, Filler, Legend, LinearScale,
  LineElement, PointElement, Title, Tooltip,
} from "chart.js";

ChartJS.register(BarElement, CategoryScale, Filler, Legend, LinearScale, LineElement, PointElement, Title, Tooltip);

const props = defineProps({ dashboard: { type: Object, required: true } });

const fmt = (n) => (n ?? 0).toLocaleString();
const shortTs = (t) => { try { return new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }); } catch { return t; } };
const timeLabel = (t) => { try { return new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); } catch { return t; } };
const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();

const stats = computed(() => [
  { label: "Current RPS", value: props.dashboard.current_rps },
  { label: "Requests (5m)", value: fmt(props.dashboard.total_requests_5m) },
  { label: "Known Bots (5m)", value: fmt(props.dashboard.total_bots_5m || 0), color: "var(--chart-orange)" },
  { label: "Suspicious (5m)", value: props.dashboard.suspicious_events_5m, color: "var(--chart-red)" },
  { label: "Max RPS (5m)", value: props.dashboard.max_rps_5m },
  { label: "Blocked IPs", value: props.dashboard.blocked_ips },
]);

const baseOpts = () => ({
  responsive: true, maintainAspectRatio: false, animation: false,
  plugins: { legend: { display: true, labels: { color: css("--chart-text"), boxWidth: 10, font: { size: 10 } } } },
  scales: {
    x: { ticks: { color: css("--chart-text"), font: { size: 9 }, maxRotation: 45 }, grid: { color: css("--chart-grid") } },
    y: { ticks: { color: css("--chart-text"), font: { size: 9 } }, grid: { color: css("--chart-grid") }, beginAtZero: true },
  },
});

const areaOpts = computed(() => { const o = baseOpts(); o.scales.x.stacked = true; o.scales.y.stacked = true; return o; });
const stackedBarOpts = computed(() => { const o = baseOpts(); o.scales.x.stacked = true; o.scales.y.stacked = true; return o; });
const barOpts = computed(() => baseOpts());
const lineOpts = computed(() => baseOpts());

const timelineChart = computed(() => {
  const tl = props.dashboard.timeline || [];
  return {
    labels: tl.map(p => timeLabel(p.t)),
    datasets: [
      { label: "Alerts", data: tl.map(p => p.problems), backgroundColor: css("--chart-red-bg"), borderColor: css("--chart-red"), borderWidth: 1, fill: true, order: 1 },
      { label: "Requests", data: tl.map(p => Math.max(0, p.requests - (p.bots || 0) - p.problems)), backgroundColor: css("--chart-blue-bg"), borderColor: css("--chart-blue"), borderWidth: 1, fill: true, order: 2 },
      { label: "Known bots", data: tl.map(p => p.bots || 0), backgroundColor: css("--chart-orange-bg"), borderColor: css("--chart-orange"), borderWidth: 1, fill: true, order: 3 },
    ],
  };
});

const countriesChart = computed(() => {
  const d = props.dashboard.top_countries || [];
  return {
    labels: d.map(r => r.name),
    datasets: [
      { label: "Requests", data: d.map(r => r.count - (r.bot_count || 0)), backgroundColor: css("--chart-blue") },
      { label: "Known bots", data: d.map(r => r.bot_count || 0), backgroundColor: css("--chart-orange") },
    ],
  };
});

const problemsChart = computed(() => {
  const d = props.dashboard.problems_timeline || [];
  return {
    labels: d.map(p => timeLabel(p.t)),
    datasets: [{ label: "Problems", data: d.map(p => p.requests), backgroundColor: css("--chart-red"), borderWidth: 1 }],
  };
});

const probRpsChart = computed(() => {
  const d = props.dashboard.problems_rps_timeline || [];
  return {
    labels: d.map(p => timeLabel(p.t)),
    datasets: [{ label: "Peak RPS", data: d.map(p => p.requests), borderColor: css("--chart-red"), backgroundColor: css("--chart-red-bg"), fill: true, tension: 0.3, pointRadius: 1 }],
  };
});

const pathsChart = computed(() => {
  const d = props.dashboard.top_problem_paths || [];
  return {
    labels: d.map(r => r.name),
    datasets: [
      { label: "Requests", data: d.map(r => r.count - (r.bot_count || 0)), backgroundColor: css("--chart-blue") },
      { label: "Known bots", data: d.map(r => r.bot_count || 0), backgroundColor: css("--chart-orange") },
    ],
  };
});

const statusChart = computed(() => {
  const d = props.dashboard.response_statuses || [];
  return {
    labels: d.map(r => r.name),
    datasets: [
      { label: "Requests", data: d.map(r => r.count - (r.bot_count || 0)), backgroundColor: css("--chart-blue") },
      { label: "Known bots", data: d.map(r => r.bot_count || 0), backgroundColor: css("--chart-orange") },
    ],
  };
});
</script>
