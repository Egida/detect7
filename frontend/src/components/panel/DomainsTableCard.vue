<template>
  <div class="card shadow-sm">
    <div class="card-body">
      <div class="d-flex justify-content-between align-items-center mb-3">
        <h5 class="card-title mb-0">Your domains</h5>
        <div class="d-flex gap-2">
          <span class="overview-link" @click="$emit('overview')">Overview</span>
          <button class="btn btn-outline-secondary btn-sm" @click="$emit('refresh')">Refresh</button>
        </div>
      </div>
      <div v-if="domains.length === 0" class="text-secondary small">No domains yet.</div>
      <div v-else class="table-responsive">
        <table class="table table-sm align-middle mb-0">
          <thead><tr><th>Domain</th><th>Status</th><th class="text-end">Actions</th></tr></thead>
          <tbody>
            <tr v-for="domain in domains" :key="domain.id" :class="{'table-active': domain.id === selectedId}">
              <td>
                <button class="btn btn-link btn-sm p-0 text-decoration-none" @click="$emit('select', domain)">
                  {{ domain.name }}
                </button>
              </td>
              <td>
                <span :class="domain.is_verified ? 'badge text-bg-success' : 'badge text-bg-warning'" style="font-size:.7rem">
                  {{ domain.is_verified ? "Verified" : "Pending" }}
                </span>
              </td>
              <td class="text-end">
                <button class="btn btn-sm btn-outline-primary me-1" @click="$emit('verify', domain.id)" style="font-size:.75rem">Verify</button>
                <button class="btn btn-sm btn-outline-danger" :disabled="!domain.is_verified" @click="$emit('delete', domain.id)" style="font-size:.75rem">Delete</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup>
defineProps({
  domains: { type: Array, default: () => [] },
  selectedId: { type: Number, default: null },
});
defineEmits(["refresh", "select", "verify", "delete", "overview"]);
</script>
