<template>
  <div class="card border-warning bg-warning-subtle mb-4 shadow-sm">
    <div class="card-body">
      <h6 class="mb-2">Verification required</h6>
      <p class="small mb-2">
        This domain is not verified yet. Analytics and all other features stay blocked until ownership is verified.
      </p>
      <div class="small mb-1">Create this file on your domain:</div>
      <div class="small"><code>{{ domain.verify_filename }}</code></div>
      <div class="small mb-3">with content: <code>{{ domain.verify_token }}</code></div>
      <button class="btn btn-primary btn-sm" @click="$emit('verify', domain.id)">Verify now</button>
    </div>
  </div>
</template>

<script setup>
defineProps({
  domain: {
    type: Object,
    required: true,
  },
});

defineEmits(["verify"]);
</script>
