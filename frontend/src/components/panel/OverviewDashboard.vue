<template>
  <div v-if="data" class="mt-3">
    <div class="row g-3 mb-3">
      <div class="col-md-3">
        <div class="stat-card">
          <div class="stat-label">Total Requests</div>
          <div class="stat-value">{{ fmt(data.total_requests) }}</div>
        </div>
      </div>
      <div class="col-md-3">
        <div class="stat-card">
          <div class="stat-label">Known Bots</div>
          <div class="stat-value" style="color: var(--chart-orange)">{{ fmt(data.total_bots) }}</div>
        </div>
      </div>
      <div class="col-md-3">
        <div class="stat-card">
          <div class="stat-label">Problems</div>
          <div class="stat-value" style="color: var(--chart-red)">{{ fmt(data.total_problems) }}</div>
        </div>
      </div>
      <div class="col-md-3">
        <div class="stat-card">
          <div class="stat-label">Current RPS</div>
          <div class="stat-value">{{ data.current_rps }}</div>
        </div>
      </div>
    </div>

    <div class="row g-3 mb-3">
      <div class="col-lg-4">
        <div class="chart-card"><h6>Requests</h6>
          <div class="chart-wrap" style="height:260px">
            <Line :data="timelineChart" :options="areaOpts" />
          </div>
        </div>
      </div>
      <div class="col-lg-4">
        <div class="chart-card"><h6>TOP 10 Domains by Requests</h6>
          <div class="chart-wrap" style="height:260px">
            <Bar :data="topDomainsReqChart" :options="stackedBarOpts" />
          </div>
        </div>
      </div>
      <div class="col-lg-4">
        <div class="chart-card"><h6>TOP 10 Countries</h6>
          <div class="chart-wrap" style="height:260px">
            <Bar :data="topCountriesChart" :options="stackedBarOpts" />
          </div>
        </div>
      </div>
    </div>

    <div class="row g-3 mb-3">
      <div class="col-lg-4">
        <div class="chart-card"><h6>Problems</h6>
          <div class="chart-wrap" style="height:260px">
            <Bar :data="problemsChart" :options="barOpts" />
          </div>
        </div>
      </div>
      <div class="col-lg-4">
        <div class="chart-card"><h6>TOP 10 Domains by Problems</h6>
          <div class="chart-wrap" style="height:260px">
            <Bar :data="topDomainsProblChart" :options="barOpts" />
          </div>
        </div>
      </div>
      <div class="col-lg-4">
        <div class="chart-card"><h6>Problems RPS</h6>
          <div class="chart-wrap" style="height:260px">
            <Line :data="probRpsChart" :options="lineOpts" />
          </div>
        </div>
      </div>
    </div>

    <div class="chart-card mb-3">
      <h6>Unique Visitors by Domain</h6>
      <div class="chart-wrap" style="height:300px">
        <Bar :data="uniqueVisChart" :options="barOpts" />
      </div>
    </div>

    <div class="chart-card mb-3" v-if="data.problem_ips.length">
      <h6>Problem IPs</h6>
      <div class="table-responsive">
        <table class="table table-sm problem-table mb-0">
          <thead><tr>
            <th>Timestamp</th><th>Domain</th><th>IP</th><th>Country</th><th>PTR</th><th>RPS (max)</th><th>Requests</th>
          </tr></thead>
          <tbody>
            <tr v-for="(ip, i) in data.problem_ips" :key="i">
              <td>{{ shortTs(ip.timestamp) }}</td>
              <td>{{ ip.domain_name }}</td>
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
  <div v-else class="text-center py-5 text-secondary">Loading overview...</div>
</template>

<script setup>
import { computed } from "vue";
import { Bar, Line } from "vue-chartjs";
import {
  BarElement, CategoryScale, Chart as ChartJS, Filler, Legend, LinearScale,
  LineElement, PointElement, Title, Tooltip,
} from "chart.js";

ChartJS.register(BarElement, CategoryScale, Filler, Legend, LinearScale, LineElement, PointElement, Title, Tooltip);

const props = defineProps({ data: { type: Object, default: null } });

const fmt = (n) => (n ?? 0).toLocaleString();
const shortTs = (t) => { try { return new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }); } catch { return t; } };
const timeLabel = (t) => { try { return new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); } catch { return t; } };

const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();

const baseOpts = () => ({
  responsive: true, maintainAspectRatio: false, animation: false,
  plugins: { legend: { display: true, labels: { color: css("--chart-text"), boxWidth: 10, font: { size: 10 } } } },
  scales: {
    x: { ticks: { color: css("--chart-text"), font: { size: 9 }, maxRotation: 45 }, grid: { color: css("--chart-grid") } },
    y: { ticks: { color: css("--chart-text"), font: { size: 9 } }, grid: { color: css("--chart-grid") }, beginAtZero: true },
  },
});

const areaOpts = computed(() => {
  const o = baseOpts();
  o.scales.x.stacked = true; o.scales.y.stacked = true;
  return o;
});
const stackedBarOpts = computed(() => {
  const o = baseOpts();
  o.scales.x.stacked = true; o.scales.y.stacked = true;
  return o;
});
const barOpts = computed(() => baseOpts());
const lineOpts = computed(() => baseOpts());

const timelineChart = computed(() => {
  const tl = props.data?.timeline || [];
  return {
    labels: tl.map(p => timeLabel(p.t)),
    datasets: [
      { label: "Alerts", data: tl.map(p => p.problems), backgroundColor: css("--chart-red-bg"), borderColor: css("--chart-red"), borderWidth: 1, fill: true, order: 1 },
      { label: "Requests", data: tl.map(p => p.requests - p.bots - p.problems), backgroundColor: css("--chart-blue-bg"), borderColor: css("--chart-blue"), borderWidth: 1, fill: true, order: 2 },
      { label: "Known bots", data: tl.map(p => p.bots), backgroundColor: css("--chart-orange-bg"), borderColor: css("--chart-orange"), borderWidth: 1, fill: true, order: 3 },
    ],
  };
});

const topDomainsReqChart = computed(() => {
  const d = props.data?.top_domains_by_requests || [];
  return {
    labels: d.map(r => r.domain_name),
    datasets: [
      { label: "Requests", data: d.map(r => r.count - r.bot_count), backgroundColor: css("--chart-blue") },
      { label: "Known bots", data: d.map(r => r.bot_count), backgroundColor: css("--chart-orange") },
    ],
  };
});

const topCountriesChart = computed(() => {
  const d = props.data?.top_countries || [];
  return {
    labels: d.map(r => r.name),
    datasets: [
      { label: "Requests", data: d.map(r => r.count - r.bot_count), backgroundColor: css("--chart-blue") },
      { label: "Known bots", data: d.map(r => r.bot_count), backgroundColor: css("--chart-orange") },
    ],
  };
});

const problemsChart = computed(() => {
  const d = props.data?.problems_timeline || [];
  return {
    labels: d.map(p => timeLabel(p.t)),
    datasets: [{ label: "Problems", data: d.map(p => p.requests), backgroundColor: css("--chart-red"), borderColor: css("--chart-red"), borderWidth: 1 }],
  };
});

const topDomainsProblChart = computed(() => {
  const d = props.data?.top_domains_by_problems || [];
  return {
    labels: d.map(r => r.domain_name),
    datasets: [{ label: "Problems", data: d.map(r => r.count), backgroundColor: css("--chart-red") }],
  };
});

const probRpsChart = computed(() => {
  const d = props.data?.problems_rps_timeline || [];
  return {
    labels: d.map(p => timeLabel(p.t)),
    datasets: [{ label: "Peak RPS", data: d.map(p => p.requests), borderColor: css("--chart-red"), backgroundColor: css("--chart-red-bg"), fill: true, tension: 0.3, pointRadius: 1 }],
  };
});

const uniqueVisChart = computed(() => {
  const d = props.data?.unique_visitors_by_domain || [];
  return {
    labels: d.map(r => r.domain_name),
    datasets: [{ label: "Unique visitors", data: d.map(r => r.count), backgroundColor: css("--chart-blue") }],
  };
});
</script>
