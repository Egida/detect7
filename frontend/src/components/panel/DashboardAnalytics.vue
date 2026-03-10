<template>
  <div class="row g-3">
    <div class="col-md-4" v-for="stat in stats" :key="stat.label">
      <div class="card shadow-sm">
        <div class="card-body">
          <div class="text-secondary small">{{ stat.label }}</div>
          <div class="h4 mb-0">{{ stat.value }}</div>
        </div>
      </div>
    </div>

    <div class="col-12">
      <div class="card shadow-sm">
        <div class="card-body">
          <h6>Requests vs suspicious events</h6>
          <div class="chart-wrap chart-wrap-lg">
            <Line :data="lineData" :options="lineOptions" :height="320" />
          </div>
        </div>
      </div>
    </div>

    <div class="col-md-6">
      <div class="card shadow-sm">
        <div class="card-body">
          <h6>Top countries</h6>
          <div class="chart-wrap">
            <Bar :data="countryData" :options="barOptions" :height="280" />
          </div>
        </div>
      </div>
    </div>
    <div class="col-md-6">
      <div class="card shadow-sm">
        <div class="card-body">
          <h6>Top problem paths</h6>
          <div class="chart-wrap">
            <Bar :data="pathData" :options="barOptions" :height="280" />
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from "vue";
import { Bar, Line } from "vue-chartjs";
import {
  CategoryScale,
  Chart as ChartJS,
  Legend,
  LinearScale,
  LineElement,
  PointElement,
  Title,
  Tooltip,
  BarElement,
} from "chart.js";

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend
);

const props = defineProps({
  dashboard: {
    type: Object,
    required: true,
  },
});

const stats = computed(() => [
  { label: "Requests (last 5m)", value: props.dashboard.total_requests_5m },
  { label: "Suspicious events (last 5m)", value: props.dashboard.suspicious_events_5m },
  { label: "Max RPS (last 5m)", value: props.dashboard.max_rps_5m },
]);

const lineData = computed(() => ({
  labels: (props.dashboard.timeline || []).map((p) =>
    new Date(p.t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
  ),
  datasets: [
    {
      label: "Requests",
      data: (props.dashboard.timeline || []).map((p) => p.requests),
      borderColor: "#0d6efd",
      backgroundColor: "rgba(13, 110, 253, 0.2)",
      tension: 0.3,
    },
    {
      label: "Problems",
      data: (props.dashboard.timeline || []).map((p) => p.problems),
      borderColor: "#dc3545",
      backgroundColor: "rgba(220, 53, 69, 0.2)",
      tension: 0.3,
    },
  ],
}));

const countryData = computed(() => ({
  labels: (props.dashboard.top_countries || []).map((p) => p.name),
  datasets: [
    {
      label: "Requests",
      data: (props.dashboard.top_countries || []).map((p) => p.count),
      backgroundColor: "#0d6efd",
    },
  ],
}));

const pathData = computed(() => ({
  labels: (props.dashboard.top_problem_paths || []).map((p) => p.name),
  datasets: [
    {
      label: "Problems",
      data: (props.dashboard.top_problem_paths || []).map((p) => p.count),
      backgroundColor: "#dc3545",
    },
  ],
}));

const lineOptions = {
  responsive: false,
  maintainAspectRatio: false,
  animation: false,
};

const barOptions = {
  responsive: false,
  maintainAspectRatio: false,
  animation: false,
};
</script>

<style scoped>
.chart-wrap {
  position: relative;
  width: 100%;
  height: 280px;
  overflow: hidden;
}

.chart-wrap-lg {
  height: 320px;
}

.chart-wrap :deep(canvas) {
  width: 100% !important;
  height: 100% !important;
  display: block;
}

@media (max-width: 768px) {
  .chart-wrap {
    height: 240px;
  }

  .chart-wrap-lg {
    height: 280px;
  }
}
</style>
