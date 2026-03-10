<template>
  <div>
    <PanelNavbar :user-email="auth.userEmail" @logout="logout" />

    <div class="container py-4">
      <div class="row g-4">
        <div class="col-lg-4">
          <AddDomainCard v-model="domainInput" :loading="domainLoading" @submit="createDomain" />
          <LogForwardingCard :instructions="instructions" />
        </div>

        <div class="col-lg-8">
          <DomainsTableCard
            :domains="domains"
            @refresh="fetchDomains"
            @select="selectDomain"
            @verify="verifyDomain"
            @delete="deleteDomain"
          />

          <VerificationRequiredCard
            v-if="selectedDomain && !selectedDomain.is_verified"
            :domain="selectedDomain"
            @verify="verifyDomain"
          />

          <DashboardAnalytics v-else-if="selectedDomain && dashboard" :dashboard="dashboard" />
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import api from "../api";
import { useAuthStore } from "../stores/auth";
import PanelNavbar from "../components/panel/PanelNavbar.vue";
import AddDomainCard from "../components/panel/AddDomainCard.vue";
import LogForwardingCard from "../components/panel/LogForwardingCard.vue";
import DomainsTableCard from "../components/panel/DomainsTableCard.vue";
import VerificationRequiredCard from "../components/panel/VerificationRequiredCard.vue";
import DashboardAnalytics from "../components/panel/DashboardAnalytics.vue";

const auth = useAuthStore();
const router = useRouter();
const domainInput = ref("");
const domains = ref([]);
const selectedDomain = ref(null);
const dashboard = ref(null);
const instructions = ref({ nginx_log_format: "", nginx_access_log_line: "", notes: [] });
const domainLoading = ref(false);

const fetchDomains = async () => {
  const { data } = await api.get("/domains");
  domains.value = data;
  if (selectedDomain.value) {
    selectedDomain.value =
      domains.value.find((domain) => domain.id === selectedDomain.value.id) || null;
  }
  if (!selectedDomain.value && domains.value.length > 0) {
    await selectDomain(domains.value[0]);
  }
};

const fetchInstructions = async () => {
  const { data } = await api.get("/domains/instructions/log-forwarding");
  instructions.value = data;
};

const createDomain = async () => {
  domainLoading.value = true;
  try {
    await api.post("/domains", { name: domainInput.value });
    domainInput.value = "";
    await fetchDomains();
  } finally {
    domainLoading.value = false;
  }
};

const verifyDomain = async (domainId) => {
  await api.post(`/domains/${domainId}/verify`);
  await fetchDomains();
  if (selectedDomain.value?.id === domainId) {
    await fetchDashboard(domainId);
  }
};

const deleteDomain = async (domainId) => {
  await api.delete(`/domains/${domainId}`);
  if (selectedDomain.value?.id === domainId) {
    selectedDomain.value = null;
    dashboard.value = null;
  }
  await fetchDomains();
};

const fetchDashboard = async (domainId) => {
  try {
    const { data } = await api.get(`/dashboard/summary/${domainId}`);
    dashboard.value = data;
  } catch (err) {
    if (err?.response?.status === 403) {
      dashboard.value = null;
      return;
    }
    throw err;
  }
};

const selectDomain = async (domain) => {
  selectedDomain.value = domain;
  dashboard.value = null;
  if (domain.is_verified) {
    await fetchDashboard(domain.id);
  }
};

const logout = () => {
  auth.logout();
  router.push("/login");
};

onMounted(async () => {
  await Promise.all([fetchDomains(), fetchInstructions()]);
});
</script>
