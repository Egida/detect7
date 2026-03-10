<template>
  <div>
    <PanelNavbar
      :user-email="auth.userEmail"
      v-model:model-range="timeRange"
      @logout="logout"
    />

    <div class="container-fluid px-4 py-3">
      <div class="row g-4">
        <div class="col-xl-3 col-lg-4">
          <AddDomainCard v-model="domainInput" :loading="domainLoading" @submit="createDomain" />

          <DomainsTableCard
            :domains="domains"
            :selected-id="selectedDomain?.id"
            @refresh="fetchDomains"
            @select="selectDomain"
            @verify="verifyDomain"
            @delete="deleteDomain"
            @overview="showOverview"
            class="mt-3"
          />

          <LogForwardingCard :instructions="instructions" class="mt-3" />
        </div>

        <div class="col-xl-9 col-lg-8">
          <VerificationRequiredCard
            v-if="selectedDomain && !selectedDomain.is_verified"
            :domain="selectedDomain"
            @verify="verifyDomain"
          />

          <OverviewDashboard
            v-else-if="!selectedDomain"
            :data="overviewData"
          />

          <DashboardAnalytics
            v-else-if="selectedDomain && dashboard"
            :dashboard="dashboard"
          />
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { onMounted, ref, watch } from "vue";
import { useRouter } from "vue-router";
import api from "../api";
import { useAuthStore } from "../stores/auth";
import PanelNavbar from "../components/panel/PanelNavbar.vue";
import AddDomainCard from "../components/panel/AddDomainCard.vue";
import LogForwardingCard from "../components/panel/LogForwardingCard.vue";
import DomainsTableCard from "../components/panel/DomainsTableCard.vue";
import VerificationRequiredCard from "../components/panel/VerificationRequiredCard.vue";
import DashboardAnalytics from "../components/panel/DashboardAnalytics.vue";
import OverviewDashboard from "../components/panel/OverviewDashboard.vue";

const auth = useAuthStore();
const router = useRouter();
const domainInput = ref("");
const domains = ref([]);
const selectedDomain = ref(null);
const dashboard = ref(null);
const overviewData = ref(null);
const instructions = ref({ nginx_log_format: "", nginx_access_log_line: "", notes: [] });
const domainLoading = ref(false);
const timeRange = ref("30m");

const fetchDomains = async () => {
  const { data } = await api.get("/domains");
  domains.value = data;
  if (selectedDomain.value) {
    selectedDomain.value = domains.value.find(d => d.id === selectedDomain.value.id) || null;
  }
};

const fetchInstructions = async () => {
  const { data } = await api.get("/domains/instructions/log-forwarding");
  instructions.value = data;
};

const fetchOverview = async () => {
  try {
    const { data } = await api.get(`/dashboard/overview?range=${timeRange.value}`);
    overviewData.value = data;
  } catch { overviewData.value = null; }
};

const fetchDashboard = async (domainId) => {
  try {
    const { data } = await api.get(`/dashboard/summary/${domainId}?range=${timeRange.value}`);
    dashboard.value = data;
  } catch (err) {
    if (err?.response?.status === 403 || err?.response?.status === 404) {
      dashboard.value = null;
      return;
    }
    throw err;
  }
};

const createDomain = async () => {
  domainLoading.value = true;
  try {
    await api.post("/domains", { name: domainInput.value });
    domainInput.value = "";
    await fetchDomains();
  } finally { domainLoading.value = false; }
};

const verifyDomain = async (domainId) => {
  await api.post(`/domains/${domainId}/verify`);
  await fetchDomains();
  if (selectedDomain.value?.id === domainId) await fetchDashboard(domainId);
};

const deleteDomain = async (domainId) => {
  await api.delete(`/domains/${domainId}`);
  if (selectedDomain.value?.id === domainId) { selectedDomain.value = null; dashboard.value = null; }
  await fetchDomains();
};

const selectDomain = async (domain) => {
  selectedDomain.value = domain;
  dashboard.value = null;
  if (domain.is_verified) await fetchDashboard(domain.id);
};

const showOverview = () => {
  selectedDomain.value = null;
  dashboard.value = null;
  fetchOverview();
};

const logout = () => { auth.logout(); router.push("/login"); };

watch(timeRange, () => {
  if (selectedDomain.value && selectedDomain.value.is_verified) {
    fetchDashboard(selectedDomain.value.id);
  } else {
    fetchOverview();
  }
});

onMounted(async () => {
  await Promise.all([fetchDomains(), fetchInstructions()]);
  fetchOverview();
});
</script>
