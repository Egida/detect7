<template>
  <div class="card shadow-sm mb-4">
    <div class="card-body">
      <div class="d-flex justify-content-between align-items-center mb-3">
        <h5 class="card-title mb-0">Your domains</h5>
        <button class="btn btn-outline-secondary btn-sm" @click="$emit('refresh')">Refresh</button>
      </div>
      <div v-if="domains.length === 0" class="text-secondary small">No domains yet.</div>
      <div v-else class="table-responsive">
        <table class="table align-middle">
          <thead>
            <tr>
              <th>Domain</th>
              <th>Status</th>
              <th>Verification file</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="domain in domains" :key="domain.id">
              <td>
                <button class="btn btn-link p-0 text-decoration-none" @click="$emit('select', domain)">
                  {{ domain.name }}
                </button>
              </td>
              <td>
                <span :class="domain.is_verified ? 'badge text-bg-success' : 'badge text-bg-warning'">
                  {{ domain.is_verified ? "Verified" : "Pending" }}
                </span>
              </td>
              <td>
                <div class="small"><code>{{ domain.verify_filename }}</code></div>
                <div class="small text-secondary">content: <code>{{ domain.verify_token }}</code></div>
              </td>
              <td class="d-flex gap-2">
                <button class="btn btn-sm btn-outline-primary" @click="$emit('verify', domain.id)">
                  Verify
                </button>
                <button
                  class="btn btn-sm btn-outline-danger"
                  :disabled="!domain.is_verified"
                  @click="$emit('delete', domain.id)"
                >
                  Delete
                </button>
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
  domains: {
    type: Array,
    default: () => [],
  },
});

defineEmits(["refresh", "select", "verify", "delete"]);
</script>
