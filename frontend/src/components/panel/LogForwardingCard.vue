<template>
  <div class="card shadow-sm mt-4">
    <div class="card-body">
      <h5 class="card-title">Log forwarding</h5>
      <p class="small text-secondary">Apply this in your Nginx config:</p>
      <pre class="p-2 rounded small" style="overflow-x:auto">{{ instructions.nginx_log_format }}</pre>
      <pre class="p-2 rounded small" style="overflow-x:auto">{{ instructions.nginx_access_log_line }}</pre>
      <ul class="small mb-0">
        <li v-for="note in instructions.notes" :key="note">{{ note }}</li>
      </ul>
    </div>
  </div>
</template>

<script setup>
defineProps({
  instructions: {
    type: Object,
    required: true,
  },
});
</script>
